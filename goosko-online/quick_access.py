"""Быстрый доступ (админская панель): фото/видео с камеры, скриншоты, питание сервера.

Модуль выделен из app.py (рефакторинг п.10). Функции, которым нужны контекст
запроса или расширения приложения (get_db, audit, send_streamable, декоратор
прав, настройки из БД), внедряются через init_app() после создания Flask-app —
так избегаем циклического импорта app <-> quick_access.
"""
import os
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
import functools
from datetime import datetime
from pathlib import Path

from flask import (
    Blueprint, Response, abort, flash, jsonify, redirect, render_template,
    request, session, url_for,
)
from flask.helpers import stream_with_context


# =====================================================================
# КОНФИГУРАЦИЯ (значения из переменных окружения; читаются при импорте,
# как и раньше в app.py — тесты выставляют env до импорта)
# =====================================================================
@dataclass(frozen=True)
class Config:
    """Конфигурация быстрого доступа (значения из окружения)."""
    video_device: str
    resolution: str
    screen_device: str
    wayland_display: str
    ffmpeg_timeout: int


ensure_dir = None  # внедряется через init_app()

QUICK_ACCESS_CONFIG = Config(
    video_device=os.environ.get("CAMERA_DEVICE", "/dev/video0"),
    resolution=os.environ.get("CAMERA_RESOLUTION", "1280x720"),
    screen_device=os.environ.get("SCREEN_DEVICE", ":1.0+0,0"),
    wayland_display=os.environ.get("WAYLAND_DISPLAY_ENV", "wayland-0"),
    ffmpeg_timeout=int(os.environ.get("FFMPEG_TIMEOUT", 30)),
)

MEDIA_DIR = Path(os.environ.get(
    "MEDIA_DIR",
    os.path.join(os.environ.get("STORAGE_DIR", "/var/www/storage"), "media"),
))

CAMERA_PHOTO_TTL = int(os.environ.get("CAMERA_PHOTO_TTL", 24 * 3600))    # 1 сутки
CAMERA_VIDEO_MAX_SECONDS = int(os.environ.get("CAMERA_VIDEO_MAX_SECONDS", 120))

POWER_ACTIONS = {
    "shutdown": (["sudo", "-n", "/usr/local/bin/goosko-power.sh", "poweroff"],
                 "Сервер выключается 🛑"),
    "reboot":   (["sudo", "-n", "/usr/local/bin/goosko-power.sh", "reboot"],
                 "Сервер перезагрушивается ♻️"),
}
POWER_CONFIRM_PHRASE = "Я УВЕРЕН"

# Строгий белый список имён медиафайлов (защита от path traversal).
MEDIA_ID_RE = re.compile(
    r"^(cam_photo|cam_video|screenshot)_\d{8}_\d{6}_[0-9a-f]{8}\.(jpg|mp4|png)$"
)

# --------- Асинхронные задачи видеозаписи (polling-статусы) ---------
# Статусы живут в БД, чтобы их видели все воркеры gunicorn.
VIDEO_TASK_TTL = 30 * 60          # запись дольше 30 минут невозможна (лимит + буфер)
TASK_DONE_TTL = 24 * 3600         # готовые статусы чистим через сутки

# --------- MJPEG-превью с камеры ---------
STREAM_MAX_AGE = 10 * 60           # поток живёт не дольше 10 минут
_streams_lock = threading.Lock()
_active_streams = {}               # username -> Popen


# =====================================================================
# ЗАВИСИМОСТИ ИЗ APP (внедряются через init_app)
# =====================================================================
app = None                # Flask app (для app_context в фоновых потоках)
get_db = None             # sqlite-соединение запроса
audit = None              # запись в журнал событий
send_streamable = None    # отдача файла с поддержкой Range

effective_camera_max_video_seconds = None
effective_camera_preview_enabled = None

_bp = None                          # единственный экземпляр Blueprint
_bp_lock = threading.Lock()

# Ленивые зависимости для декораторов (внедряются в init_app):
_admin_required = None              # admin_required из app.py
_rate_limiter = None                # FlaskLimiter из app.py


def admin_required(f):
    """Обёртка над admin_required из app.py (он определён позже импорта qa)."""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        return _admin_required(f)(*args, **kwargs)
    return wrapped


def rate_limit(rule):
    """Ленивый limiter.limit(...): сам лимит применяется при первом запросе."""
    def deco(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            nonlocal f
            if getattr(wrapped, "_rl", None) is None:
                wrapped._rl = _rate_limiter.limit(rule)(f)
            return wrapped._rl(*args, **kwargs)
        wrapped._rl = None
        return wrapped
    return deco


def make_blueprint():
    """Создаёт (ОДИН раз) и возвращает Blueprint с маршрутами /quick/*.

    Декораторы здесь — наши ленивые обёртки (см. выше), поэтому порядок
    определения функций в app.py не важен. Повторный импорт app.py (тесты
    чистят sys.modules) переиспользует тот же объект Blueprint — Flask не
    падает на дубликате имени, а app.register_blueprint вызывается заново
    для нового экземпляра приложения.
    """
    global _bp
    with _bp_lock:
        if _bp is not None:
            return _bp
        bp = Blueprint("quick_access", __name__)

        bp.add_url_rule("/quick", "quick_access_page",
                        admin_required(quick_access_page))
        bp.add_url_rule("/quick/capture/photo", "quick_capture_photo",
                        admin_required(rate_limit("20 per hour")(
                            quick_capture_photo)), methods=["POST"])
        bp.add_url_rule("/quick/capture/video", "quick_capture_video",
                        admin_required(rate_limit("10 per hour")(
                            quick_capture_video)), methods=["POST"])
        bp.add_url_rule("/quick/task/<task_id>", "quick_video_status",
                        admin_required(quick_video_status))
        bp.add_url_rule("/quick/capture/screenshot",
                        "quick_capture_screenshot",
                        admin_required(rate_limit("30 per hour")(
                            quick_capture_screenshot)), methods=["POST"])
        bp.add_url_rule("/quick/media/<media_id>", "quick_media_view",
                        admin_required(quick_media_view))
        bp.add_url_rule("/quick/delete", "quick_delete_media",
                        admin_required(quick_delete_media), methods=["POST"])
        bp.add_url_rule("/quick/purge", "quick_purge_media",
                        admin_required(quick_purge_media), methods=["POST"])
        bp.add_url_rule("/quick/power/<action>", "quick_power",
                        admin_required(rate_limit("5 per hour")(
                            quick_power)), methods=["POST"])
        bp.add_url_rule("/quick/stream.mjpg", "quick_camera_stream",
                        admin_required(quick_camera_stream))
        _bp = bp
        return bp


def init_app(flask_app, *, get_db_fn, audit_fn, send_streamable_fn,
             admin_required_fn, max_video_seconds_fn, preview_enabled_fn,
             ensure_dir_fn, limiter):
    """Внедряет зависимости из app.py (вызывается при импорте app.py)."""
    global app, get_db, audit, send_streamable, ensure_dir
    global effective_camera_max_video_seconds, effective_camera_preview_enabled
    global _admin_required, _rate_limiter

    app = flask_app
    get_db = get_db_fn
    audit = audit_fn
    send_streamable = send_streamable_fn
    ensure_dir = ensure_dir_fn
    _admin_required = admin_required_fn
    _rate_limiter = limiter
    effective_camera_max_video_seconds = max_video_seconds_fn
    effective_camera_preview_enabled = preview_enabled_fn

    ensure_dir(str(MEDIA_DIR))


def _logger():
    return app.logger


# =====================================================================
# НИЗКОУРОВНЕВНЫЕ ХЕЛПЕРЫ
# =====================================================================
def run_cmd(cmd, timeout=30, env=None):
    """Запуск команды без shell (списком аргументов). -> (ok, stdout, stderr)"""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env,
        )
        return proc.returncode == 0, proc.stdout, proc.stderr
    except FileNotFoundError:
        return False, "", f"Не найдена программа: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "", f"Превышен таймаут ({timeout} с): {' '.join(cmd[:3])}…"
    except Exception as exc:  # защита от любых ошибок запуска
        _logger().exception("run_cmd failed")
        return False, "", str(exc)


def quick_access_env():
    """Окружение для grab (нужен доступ к сессии Wayland)."""
    environ = os.environ.copy()
    environ.setdefault("WAYLAND_DISPLAY", QUICK_ACCESS_CONFIG.wayland_display)
    environ.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    environ.setdefault("DBUS_SESSION_BUS_ADDRESS",
                       f"unix:path={environ['XDG_RUNTIME_DIR']}/bus")
    return environ


def _cleanup_failed_capture(filepath):
    if filepath.exists():
        try:
            filepath.unlink()
        except OSError:
            pass


def capture_photo(config: Config) -> tuple[bool, str]:
    """Делает фото с веб-камеры."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = MEDIA_DIR / f"cam_photo_{timestamp}_{uuid.uuid4().hex[:8]}.jpg"

    ok, _, err = run_cmd([
        "ffmpeg", "-y",
        "-f", "v4l2", "-video_size", config.resolution,
        "-i", config.video_device,
        "-vframes", "1",
        "-ss", "00:00:02",
        str(filepath)
    ], timeout=config.ffmpeg_timeout)

    if not ok or not filepath.exists():
        _cleanup_failed_capture(filepath)
        return False, err.strip() or "Ошибка ffmpeg"
    return True, str(filepath)


def capture_video(config: Config, duration: int) -> tuple[bool, str]:
    """Записывает видео с веб-камеры."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = MEDIA_DIR / f"cam_video_{timestamp}_{uuid.uuid4().hex[:8]}.mp4"

    ok, _, err = run_cmd([
        "ffmpeg", "-y",
        "-f", "v4l2", "-video_size", config.resolution,
        "-i", config.video_device,
        "-t", str(duration),
        "-c:v", "libx264", "-preset", "fast",
        "-pix_fmt", "yuv420p",
        str(filepath)
    ], timeout=config.ffmpeg_timeout + duration + 10)

    if not ok or not filepath.exists():
        _cleanup_failed_capture(filepath)
        return False, err.strip() or "Ошибка ffmpeg"
    return True, str(filepath)


def capture_screenshot(config: Config) -> tuple[bool, str]:
    """Делает скриншот экрана сервера (grab — для X11/Wayland через PipeWire)."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = MEDIA_DIR / f"screenshot_{timestamp}_{uuid.uuid4().hex[:8]}.png"

    ok, _, err = run_cmd(
        ["grab", "--filename", str(filepath), config.screen_device],
        timeout=config.ffmpeg_timeout, env=quick_access_env(),
    )
    if not ok or not filepath.exists():
        _cleanup_failed_capture(filepath)
        return False, err.strip() or "grab не установлен или экран недоступен"
    return True, str(filepath)


def resolve_media_file(media_id):
    """Строго по белому списку имён находим файл медиа (защита от path traversal)."""
    if not MEDIA_ID_RE.fullmatch(media_id or ""):
        return None
    path = MEDIA_DIR / media_id
    if not path.is_file():
        return None
    return str(path)


def cleanup_media_files(max_age_hours=CAMERA_PHOTO_TTL // 3600):
    """Удаляет устаревшие медиа быстрой съёмки. Возвращает число удалённых."""
    cutoff = time.time() - max_age_hours * 3600
    removed = 0
    try:
        for p in MEDIA_DIR.iterdir():
            if not MEDIA_ID_RE.fullmatch(p.name):
                continue
            try:
                if p.is_file() and p.stat().st_mtime < cutoff:
                    p.unlink()
                    removed += 1
            except OSError:
                _logger().exception("Failed to purge media %s", p)
    except OSError:
        pass
    return removed


# =====================================================================
# ФОНОВЫЕ ЗАДАЧИ ВИДЕО (таблица tasks — в users.db, видна всем воркерам)
# =====================================================================
def _task_row(task_id):
    db = get_db()
    return db.execute(
        "SELECT status, filename, duration, error FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()


def cleanup_tasks():
    """Удаляет зависшие/устаревшие записи задач."""
    now = time.time()
    db = get_db()
    db.execute(
        "DELETE FROM tasks WHERE status = 'running' AND started_at < ?",
        (now - VIDEO_TASK_TTL,),
    )
    db.execute(
        "DELETE FROM tasks WHERE status != 'running' AND started_at < ?",
        (now - TASK_DONE_TTL,),
    )
    db.commit()


def _run_video_task(task_id: str, duration: int):
    """Выполняется в отдельном потоке: пишет видео и обновляет статус в БД.

    Весь код работает внутри application context — иначе get_db()/audit()
    падают с RuntimeError: Working outside of application context.
    """
    with app.app_context():
        try:
            ok, info = capture_video(QUICK_ACCESS_CONFIG, duration)
            db = get_db()
            if ok:
                db.execute(
                    "UPDATE tasks SET status='done', filename=? WHERE id=?",
                    (os.path.basename(info), task_id),
                )
                db.commit()
                audit("quick_video", f"{os.path.basename(info)} ({duration}s)")
            else:
                db.execute(
                    "UPDATE tasks SET status='error', error=? WHERE id=?",
                    (info[:500], task_id),
                )
                db.commit()
        except Exception as exc:
            _logger().exception("video task %s failed", task_id)
            try:
                db = get_db()
                db.execute("UPDATE tasks SET status='error', error=? WHERE id=?",
                           (str(exc)[:500], task_id))
                db.commit()
            except Exception:
                pass


def _terminate_stream(proc):
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    except OSError:
        pass


# =====================================================================
# МАРШРУТЫ (регистрируются в make_blueprint с ленивыми декораторами)
# =====================================================================


def quick_access_page():
    media = []
    try:
        for p in sorted(MEDIA_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if p.is_file() and MEDIA_ID_RE.fullmatch(p.name):
                kind = "Фото" if p.name.startswith("cam_photo") else \
                       "Видео" if p.name.startswith("cam_video") else "Скриншот"
                media.append({
                    "id": p.name,
                    "kind": kind,
                    "size": p.stat().st_size,
                    "mtime": datetime.fromtimestamp(p.stat().st_mtime).strftime("%d.%m.%Y %H:%M"),
                    # jpg/png отдаём как <img>-превью прямо из quick_media_view
                    "thumb": p.name.startswith(("cam_photo", "screenshot")),
                })
            if len(media) >= 100:
                break
    except OSError:
        _logger().exception("Failed to list media dir")

    return render_template(
        "quick.html",
        config=QUICK_ACCESS_CONFIG,
        media=media,
        max_video_seconds=effective_camera_max_video_seconds(),
        preview_enabled=effective_camera_preview_enabled(),
        photo_ttl_hours=CAMERA_PHOTO_TTL // 3600,
        confirm_phrase=POWER_CONFIRM_PHRASE,
    )


def quick_capture_photo():
    cleanup_media_files()
    ok, info = capture_photo(QUICK_ACCESS_CONFIG)
    if ok:
        audit("quick_photo", os.path.basename(info))
        flash(f"✅ Фото снято: {os.path.basename(info)}")
    else:
        flash(f"❌ Не удалось сделать фото: {info[:300]}")
    return redirect(url_for("quick_access.quick_access_page"))


def quick_capture_video():
    try:
        duration = int(request.form.get("duration", 10))
    except (TypeError, ValueError):
        duration = 0
    max_seconds = effective_camera_max_video_seconds()
    if not (1 <= duration <= max_seconds):
        flash(f"❌ Длительность: от 1 до {max_seconds} секунд")
        return redirect(url_for("quick_access.quick_access_page"))

    cleanup_media_files()
    with app.app_context():
        cleanup_tasks()

    # Запись идёт в отдельном потоке — страница не блокируется на минуты.
    task_id = uuid.uuid4().hex
    db = get_db()
    db.execute(
        "INSERT INTO tasks (id, status, duration, started_at) VALUES (?, 'running', ?, ?)",
        (task_id, duration, time.time()),
    )
    db.commit()
    threading.Thread(
        target=_run_video_task, args=(task_id, duration),
        daemon=True, name=f"goosko-video-{task_id[:8]}",
    ).start()
    audit("quick_video_started", f"{duration}s task={task_id[:8]}")

    if request.accept_mimetypes.best_match(
            ["application/json", "text/html"]) == "application/json":
        return jsonify({"ok": True, "task_id": task_id, "duration": duration})
    flash("⏳ Запись видео началась — статус обновится автоматически.")
    return redirect(url_for("quick_access.quick_access_page"))


def quick_video_status(task_id):
    """JSON-статус фоновой видеозаписи для polling."""
    if not re.fullmatch(r"[0-9a-f]{32}", task_id or ""):
        abort(404)
    row = _task_row(task_id)
    if row is None:
        abort(404)
    payload = {"status": row["status"], "duration": row["duration"]}
    if row["status"] == "done":
        payload["filename"] = row["filename"]
        payload["view_url"] = url_for("quick_access.quick_media_view",
                                      media_id=row["filename"])
    elif row["status"] == "error":
        payload["error"] = (row["error"] or "Ошибка записи")[:300]
    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def quick_capture_screenshot():
    cleanup_media_files()
    ok, info = capture_screenshot(QUICK_ACCESS_CONFIG)
    if ok:
        audit("quick_screenshot", os.path.basename(info))
        flash(f"✅ Скриншот сделан: {os.path.basename(info)}")
    else:
        flash(f"❌ Не удалось сделать скриншот: {info[:300]}")
    return redirect(url_for("quick_access.quick_access_page"))


def quick_media_view(media_id):
    path = resolve_media_file(media_id)
    if path is None:
        abort(404)
    mimetype = {
        ".jpg": "image/jpeg", ".png": "image/png", ".mp4": "video/mp4",
    }.get(os.path.splitext(media_id)[1].lower())
    resp = send_streamable(path, mimetype=mimetype, download_name=media_id)
    resp.headers["Cache-Control"] = "private, no-store"
    resp.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
    return resp


def quick_delete_media():
    media_id = request.form.get("id", "")
    path = resolve_media_file(media_id)
    if path is None:
        flash("❌ Файл не найден")
    else:
        try:
            os.remove(path)
            audit("quick_media_deleted", media_id)
            flash(f"🗑️ Удалено: {media_id}")
        except OSError:
            flash("❌ Не удалось удалить файл")
    return redirect(url_for("quick_access.quick_access_page"))


def _list_media_ids():
    ids = []
    try:
        for p in MEDIA_DIR.iterdir():
            if p.is_file() and MEDIA_ID_RE.fullmatch(p.name):
                ids.append(p.name)
    except OSError:
        pass
    return ids


def quick_purge_media():
    n = 0
    for name in _list_media_ids():
        try:
            (MEDIA_DIR / name).unlink()
            n += 1
        except OSError:
            _logger().exception("Failed to purge media %s", name)
    audit("quick_media_purged", f"{n} files")
    flash(f"🧹 Удалено медиафайлов: {n}")
    return redirect(url_for("quick_access.quick_access_page"))


def quick_power(action):
    if action not in POWER_ACTIONS:
        abort(404)
    cmd, message = POWER_ACTIONS[action]

    # Обязательное подтверждение фразой — защита от случайного/CSRF выключения.
    if request.form.get("confirm", "").strip() != POWER_CONFIRM_PHRASE:
        flash(f"❌ Для подтверждения введите фразу «{POWER_CONFIRM_PHRASE}»")
        return redirect(url_for("quick_access.quick_access_page"))

    audit(f"quick_{action}", "requested")
    ok, _, err = run_cmd(cmd, timeout=15)
    if ok:
        flash(message)
        # Страница после выключения будет недоступна — редиректим на логин.
        return redirect(url_for("index"))
    flash(f"❌ Не удалось выполнить команду: {err.strip()[:300]}")
    return redirect(url_for("quick_access.quick_access_page"))


def quick_camera_stream():
    """Живое MJPEG-превью камеры (ffmpeg -> multipart/x-mixed-replace)."""
    user = session.get("user", "?")
    with _streams_lock:
        old = _active_streams.pop(user, None)
    if old is not None:
        _terminate_stream(old)

    try:
        proc = subprocess.Popen(
            ["ffmpeg", "-nostdin", "-y",
             "-f", "v4l2", "-input_format", "mjpeg",
             "-video_size", QUICK_ACCESS_CONFIG.resolution,
             "-i", QUICK_ACCESS_CONFIG.video_device,
             "-c:v", "copy",
             "-f", "mpjpeg", "-boundary_ptz", "preview",
             "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        abort(502, description=f"Не удалось запустить поток камеры: {exc}")

    _active_streams[user] = proc
    deadline = time.monotonic() + STREAM_MAX_AGE

    def generate():
        try:
            while time.monotonic() < deadline and proc.poll() is None:
                chunk = proc.stdout.read(8192)
                if not chunk:
                    break
                yield chunk
        finally:
            with _streams_lock:
                if _active_streams.get(user) is proc:
                    del _active_streams[user]
            _terminate_stream(proc)

    resp = Response(stream_with_context(generate()),
                    mimetype="multipart/x-mixed-replace; boundary=preview")
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp
