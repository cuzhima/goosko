from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, send_file, abort, g, Response, jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import safe_join
from werkzeug.exceptions import HTTPException
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import sqlite3
import functools
import atexit
import os
import secrets
import re
import unicodedata
import hashlib
import hmac
import time
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
from flask.helpers import stream_with_context


# =====================================================================
# ИСКЛЮЧЕНИЯ
# =====================================================================
class UploadTooLarge(Exception):
    pass


class QuotaExceeded(Exception):
    pass


# =====================================================================
# ПУТИ И ХРАНИЛИЩЕ
# =====================================================================
def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o750)
    except OSError:
        pass


STORAGE_DIR = os.environ.get("STORAGE_DIR", "/var/www/storage")
PUBLIC_DIR = os.path.join(STORAGE_DIR, "public")
PRIVATE_DIR = os.path.join(STORAGE_DIR, "private")
TRASH_DIR = os.path.join(STORAGE_DIR, "trash")

for d in (STORAGE_DIR, PUBLIC_DIR, PRIVATE_DIR, TRASH_DIR):
    ensure_dir(d)


# =====================================================================
# КОНФИГИ
# =====================================================================
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", 4 * 1024 * 1024 * 1024))
USER_QUOTA = int(os.environ.get("USER_QUOTA", 20 * 1024 * 1024 * 1024))
TOKEN_TTL = int(os.environ.get("UPLOAD_TOKEN_TTL", 3600))
SHARE_TTL_HOURS = int(os.environ.get("SHARE_TTL_HOURS", 24))

FUNNEL_HOST = os.environ.get(
    "FUNNEL_HOST", "https://andrey-monoblock.tail098776.ts.net"
)
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://goosko.online").rstrip("/")

USE_X_ACCEL = os.environ.get("USE_X_ACCEL", "1") == "1"

DB = os.environ.get("DB_PATH", "users.db")

# В dev-режиме (STORAGE_DIR не задан) считаем, что это локальная разработка:
# ослабляем cookie-требования и не включаем строгий HSTS.
IS_DEV = os.environ.get("STORAGE_DIR") is None


# =====================================================================
# FLASK APP
# =====================================================================
app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Нужно задать переменную окружения SECRET_KEY")

app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_SECURE=not IS_DEV,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE,
    WTF_CSRF_TIME_LIMIT=3600,
    WTF_CSRF_SSL_STRICT=False,
    PREFERRED_URL_SCHEME="https",
    # Усиленное хеширование паролей (scrypt вместо слабых по умолчанию pbkdf2/hex)
    PW_HASH_METHOD="scrypt",
)

# Поддержка Cloudflare и Tailscale Funnel
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

csrf = CSRFProtect(app)


def _manual_csrf_ok() -> bool:
    """Ручная проверка CSRF-токена (поле формы или заголовок X-CSRFToken).

    Используется в маршрутах с @csrf.exempt, где токен передаётся из JS
    (fetch/XHR) — возвращает True только при валидном токене.
    """
    from flask_wtf.csrf import validate_csrf
    from wtforms import ValidationError

    token = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRFToken")
        or request.headers.get("X-CSRF-Token")
    )
    try:
        validate_csrf(token)
        return True
    except ValidationError:
        return False


# Ограничение частоты запросов. Ключ — реальный IP клиента (с учётом
# Cloudflare/Tailscale через ProxyFix), а не адрес прокси.
def client_key():
    return get_remote_address() or "unknown"

limiter = Limiter(
    key_func=client_key,
    app=app,
    default_limits=["200 per hour", "30 per minute"],
    storage_uri="memory://",
    enabled=os.environ.get("RATELIMIT_ENABLED", "1") == "1",
)


# =====================================================================
# ⚡ БЫСТРЫЙ ДОСТУП — вынесен в модуль quick_access.py (рефакторинг п.10).
# init_app внедряет зависимости (БД, аудит, права, отдача файлов) и
# регистрирует blueprint. Все зависимости передаются лениво: функции
# определены ниже по ходу app.py, а вызываются только при обработке
# запросов. Blueprint создаётся здесь же и регистрируется сразу —
# иначе при повторном импорте app.py (тесты чистят sys.modules) новый
# объект Flask не получил бы маршруты /quick/*.
# =====================================================================
import quick_access as qa

qa_bp = qa.make_blueprint()
app.register_blueprint(qa_bp)

qa.init_app(
    app,
    get_db_fn=lambda: get_db(),
    audit_fn=lambda *a, **k: audit(*a, **k),
    send_streamable_fn=lambda *a, **k: send_streamable(*a, **k),
    admin_required_fn=lambda f: admin_required(f),
    max_video_seconds_fn=lambda: effective_camera_max_video_seconds(),
    preview_enabled_fn=lambda: effective_camera_preview_enabled(),
    ensure_dir_fn=ensure_dir,
    limiter=limiter,
)
MEDIA_DIR = qa.MEDIA_DIR
CAMERA_VIDEO_MAX_SECONDS = qa.CAMERA_VIDEO_MAX_SECONDS


# =====================================================================
# ДИНАМИЧЕСКИЙ COOKIE_DOMAIN (для goosko.online + Tailscale Funnel)
# =====================================================================
@app.before_request
def set_dynamic_cookie_domain():
    host = (request.host or "").split(":")[0].lower()
    if host == "goosko.online" or host.endswith(".goosko.online"):
        app.config["SESSION_COOKIE_DOMAIN"] = ".goosko.online"
    elif host.endswith(".ts.net"):
        # Точный allow-list нашего Funnel-хоста: нельзя ставить cookie-domain
        # из заголовка Host, который контролирует атакующий.
        funnel_host = FUNNEL_HOST.split("://")[-1].split("/")[0].lower()
        if host == funnel_host or host.endswith("." + funnel_host):
            app.config["SESSION_COOKIE_DOMAIN"] = host
        else:
            app.config["SESSION_COOKIE_DOMAIN"] = None
    else:
        app.config["SESSION_COOKIE_DOMAIN"] = None


# =====================================================================
# ИМЕНА ФАЙЛОВ
# =====================================================================
def secure_filename(filename):
    """Безопасное имя файла с поддержкой Unicode."""
    if not filename:
        return ""
    filename = unicodedata.normalize("NFKC", filename)
    filename = filename.replace("\\", "/").split("/")[-1]
    filename = re.sub(r'[\x00-\x1f\x7f<>:"|?*;/]', "_", filename)
    filename = filename.strip(". ")
    return filename[:255] if filename else ""


UNSAFE_PUBLIC_EXTENSIONS = {
    ".html", ".htm", ".xhtml", ".svg", ".xml",
    ".js", ".mjs", ".php", ".phtml", ".php3", ".php5",
    ".cgi", ".pl", ".py", ".sh", ".bat", ".cmd",
    ".ps1", ".dll", ".exe", ".msi", ".htaccess",
}

# Расширения, которые отдаём в браузере как есть (просмотр).
INLINE_SAFE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico",
    ".tif", ".tiff", ".heic", ".heif",
    ".pdf", ".txt", ".md", ".csv", ".log", ".json",
    ".mp3", ".ogg", ".wav", ".flac", ".m4a",
    ".mp4", ".webm", ".mov", ".m4v",
}


def is_safe_public_filename(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext not in UNSAFE_PUBLIC_EXTENSIONS


def is_inline_safe(filename):
    """Файл можно показывать в браузере инлайнно (с изоляцией по домену)."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in INLINE_SAFE_EXTENSIONS and not is_hidden_dotfile(filename)


def is_hidden_dotfile(filename):
    base = os.path.basename(filename)
    return base.startswith(".")


# =====================================================================
# БАЗА ДАННЫХ
# =====================================================================
def add_column(conn, table, column, ctype):
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ctype}")
    except sqlite3.OperationalError:
        pass


def init_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            zone TEXT NOT NULL CHECK(zone IN ('public','private')),
            rel_path TEXT NOT NULL,
            original_name TEXT NOT NULL,
            size INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            deleted_at TEXT,
            trash_path TEXT,
            share_token TEXT,
            share_expires_at TEXT,
            download_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS ssh_certs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial INTEGER NOT NULL,
            identity TEXT NOT NULL,
            principal TEXT NOT NULL,
            ttl_minutes INTEGER NOT NULL,
            cert_text TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            revoked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_files_share ON files(share_token);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_files_active
            ON files(zone, rel_path) WHERE deleted_at IS NULL;
        CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner);
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'running',
            filename TEXT,
            error TEXT,
            duration INTEGER,
            started_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_files_zone ON files(zone);
    """)

    # Миграции старых БД
    for table, column, ctype in [
        ("files", "trash_path", "TEXT"),
        ("files", "share_token", "TEXT"),
        ("files", "share_expires_at", "TEXT"),
        ("files", "download_count", "INTEGER NOT NULL DEFAULT 0"),
        # Точный (мс) момент загрузки: created_at в SQLite имеет точность
        # до секунды — файлы, загруженные в одну секунду, сортировались
        # неверно. created_ms заполняется приложением.
        ("files", "created_ms", "REAL"),
    ]:
        add_column(conn, table, column, ctype)

    # Backfill created_ms для старых записей (приблизительно из created_at).
    conn.execute(
        "UPDATE files SET created_ms = strftime('%s', created_at) * 1000 "
        "WHERE created_ms IS NULL AND created_at IS NOT NULL"
    )

    # Миграция старых БД: таблица задач быстрой видеосъёмки.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'running',
            filename TEXT,
            error TEXT,
            duration INTEGER,
            started_at REAL NOT NULL
        )
    """)

    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        admin_password = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(16)
        conn.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
            ("admin", generate_password_hash(admin_password)),
        )
        if not os.environ.get("ADMIN_PASSWORD"):
            print("=" * 80)
            print("Создан пользователь admin. Одноразовый пароль:")
            print(admin_password)
            print("Смени его сразу после входа!")
            print("=" * 80)

    # Настройки по умолчанию
    defaults = {
        "trash_retention_days": str(int(os.environ.get("TRASH_RETENTION_DAYS", 30))),
        "user_quota_bytes": str(USER_QUOTA),
        "max_file_size_bytes": str(MAX_FILE_SIZE),
        "share_ttl_hours": str(SHARE_TTL_HOURS),
        "stream_uploads": os.environ.get("STREAM_UPLOADS", "1"),
    }
    for key, value in defaults.items():
        try:
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                (key, value),
            )
        except sqlite3.Error:
            pass

    conn.commit()
    conn.close()


def get_setting(key, default=None):
    row = get_db().execute(
        "SELECT value FROM settings WHERE key = ?", (key,)
    ).fetchone()
    return row["value"] if row else default


def get_int_setting(key, default):
    try:
        return int(get_setting(key))
    except (TypeError, ValueError):
        return default


def effective_user_quota():
    """Квота пользователя (админы — без ограничений)."""
    return get_int_setting("user_quota_bytes", USER_QUOTA)


def effective_max_file_size():
    return get_int_setting("max_file_size_bytes", MAX_FILE_SIZE)


def effective_share_ttl_hours():
    return get_int_setting("share_ttl_hours", SHARE_TTL_HOURS)


def effective_trash_retention_days():
    return max(0, get_int_setting("trash_retention_days", 30))


def effective_stream_uploads():
    """Потоковая (chunked) отдача файлов с Range вместо whole-file send_file."""
    return get_int_setting("stream_uploads", 1) == 1


def effective_camera_max_video_seconds():
    return max(1, get_int_setting(
        "camera_max_video_seconds", CAMERA_VIDEO_MAX_SECONDS))


def effective_camera_preview_enabled():
    """Живое MJPEG-превью камеры на странице Быстрого доступа."""
    return get_int_setting("camera_preview_enabled", 1) == 1


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


init_db()

# Фоновая автоочистка корзины/медиа/SSH-бандлов запускается только при
# реальной работе сервера (не под pytest, чтобы не плодить потоки в тестах).
if os.environ.get("GOOSKO_DISABLE_MAINTENANCE") != "1":
    start_background_maintenance()


# =====================================================================
# ФИЛЬТРЫ И ВРЕМЯ
# =====================================================================
@app.template_filter("human_size")
def human_size(value):
    try:
        size = float(value or 0)
    except Exception:
        return "0 Б"
    for unit in ["Б", "КБ", "МБ", "ГБ", "ТБ"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} ПБ"


def utcnow():
    return datetime.now(timezone.utc)


def dbnow(dt=None):
    if dt is None:
        dt = utcnow()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_db_dt(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@app.context_processor
def inject_globals():
    return {
        "public_base_url": PUBLIC_BASE_URL,
        "funnel_host": FUNNEL_HOST,
        "user_quota": USER_QUOTA,
    }


# =====================================================================
# АУДИТ
# =====================================================================
def audit(action, details=""):
    try:
        username = session.get("user", "anonymous")
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (username, action, details, ip) VALUES (?,?,?,?)",
            (username, action, details, request.remote_addr),
        )
        db.commit()
    except Exception:
        app.logger.exception("Audit failed")


# =====================================================================
# ДЕКОРАТОРЫ
# =====================================================================
def login_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            # Запоминаем, куда хотел пойти пользователь (только внутренние пути)
            next_url = sanitize_next(request.full_path.rstrip("?"))
            return redirect(url_for("index", next=next_url) if next_url else url_for("index"))
        return f(*args, **kwargs)
    return wrapped


def admin_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("index"))
        if not session.get("is_admin"):
            abort(403)
        return f(*args, **kwargs)
    return wrapped


# =====================================================================
# ВАЛИДАЦИЯ
# =====================================================================
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{3,32}$")


def valid_username(username):
    return bool(username and USERNAME_RE.fullmatch(username))


def password_problem(password):
    if len(password) < 10:
        return "Пароль должен быть не короче 10 символов"
    if not any(c.isalpha() for c in password):
        return "Пароль должен содержать буквы"
    if not any(c.isdigit() for c in password):
        return "Пароль должен содержать цифры"
    return None


# =====================================================================
# ПОЛЬЗОВАТЕЛИ И КВОТЫ
# =====================================================================
def get_user_row(username):
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def is_admin_username(username):
    row = get_user_row(username)
    return bool(row and row["is_admin"])


def get_user_usage(username):
    row = get_db().execute(
        "SELECT COALESCE(SUM(size), 0) AS total FROM files WHERE owner = ? AND deleted_at IS NULL",
        (username,),
    ).fetchone()
    return row["total"] if row else 0


def quota_remaining(username):
    if is_admin_username(username):
        return None
    return max(0, effective_user_quota() - get_user_usage(username))


# =====================================================================
# КОРЗИНА: ВОССТАНОВЛЕНИЕ / ОЧИСТКА
# =====================================================================
def get_trash_file_by_id(file_id):
    return get_db().execute(
        "SELECT * FROM files WHERE id=? AND deleted_at IS NOT NULL", (file_id,)
    ).fetchone()


def resolve_trash_path(row):
    """Безопасно собираем физический путь файла в корзине."""
    name = os.path.basename(row["trash_path"] or "")
    if not name:
        return None
    path = safe_join(TRASH_DIR, name)
    if path is None:
        return None
    base_real = os.path.realpath(TRASH_DIR)
    path_real = os.path.realpath(path)
    if not path_real.startswith(base_real + os.sep):
        return None
    return path


def purge_trash_files(max_age_days=None):
    """Удаляет файлы из корзины старше max_age_days. Возвращает число."""
    if max_age_days is None:
        max_age_days = effective_trash_retention_days()
    db = get_db()
    rows = db.execute(
        "SELECT * FROM files WHERE deleted_at IS NOT NULL"
    ).fetchall()
    cutoff = utcnow() - timedelta(days=max_age_days)
    purged = 0
    for row in rows:
        deleted = parse_db_dt(row["deleted_at"])
        if not deleted or deleted > cutoff:
            continue
        path = resolve_trash_path(row)
        if path and os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                app.logger.exception("Failed to purge %s", path)
                continue
        db.execute("DELETE FROM files WHERE id=?", (row["id"],))
        purged += 1
    if purged:
        db.commit()
    return purged


def start_background_maintenance():
    """Раз в сутки: чистим корзину, устаревшие медиа и SSH-бандлы."""
    def worker():
        while True:
            time.sleep(24 * 3600)
            try:
                with app.app_context():
                    n = purge_trash_files()
                    if n:
                        app.logger.info("Trash cleanup: purged %d old files", n)
            except Exception:
                app.logger.exception("Background trash cleanup failed")
            try:
                m = qa.cleanup_media_files()
                if m:
                    app.logger.info("Media cleanup: removed %d files", m)
            except Exception:
                app.logger.exception("Background media cleanup failed")
            try:
                ssh_bundles_cleanup()
            except Exception:
                app.logger.exception("SSH bundles cleanup failed")
            try:
                with app.app_context():
                    qa.cleanup_tasks()
            except Exception:
                app.logger.exception("Tasks cleanup failed")

    t = threading.Thread(target=worker, daemon=True, name="goosko-maintenance")
    t.start()


# =====================================================================
# БЕЗОПАСНЫЕ ПУТИ
# =====================================================================
def resolve_storage_path(base_dir, rel_path):
    if not rel_path:
        return None
    rel_path = os.path.normpath(rel_path).lstrip("/")
    if rel_path in ("", ".", "..") or rel_path.startswith(".."):
        return None
    path = safe_join(base_dir, rel_path)
    if path is None:
        return None
    base_real = os.path.realpath(base_dir)
    path_real = os.path.realpath(path)
    if path_real != base_real and not path_real.startswith(base_real + os.sep):
        return None
    return path


def safe_storage_path(base_dir, rel_path):
    path = resolve_storage_path(base_dir, rel_path)
    if path is None:
        abort(403)
    return path


def get_user_private_dir(username):
    username = secure_filename(username)
    path = os.path.join(PRIVATE_DIR, username)
    ensure_dir(path)
    return path


def can_access_private(current_user, is_admin, target_user):
    return bool(is_admin) or current_user == target_user


# =====================================================================
# ФАЙЛЫ В БД
# =====================================================================
def active_file_exists(zone, rel_path):
    row = get_db().execute(
        "SELECT id FROM files WHERE zone=? AND rel_path=? AND deleted_at IS NULL",
        (zone, rel_path),
    ).fetchone()
    return bool(row)


def get_active_file_by_id(file_id):
    return get_db().execute(
        "SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (file_id,)
    ).fetchone()


def get_active_file_by_path(zone, rel_path):
    return get_db().execute(
        "SELECT * FROM files WHERE zone=? AND rel_path=? AND deleted_at IS NULL",
        (zone, rel_path),
    ).fetchone()


def unique_rel_path(base_dir, prefix, filename, zone):
    name, ext = os.path.splitext(filename)
    used_names = {filename}
    candidate = filename
    for _ in range(100):
        rel = f"{prefix}/{candidate}" if prefix else candidate
        physical = resolve_storage_path(base_dir, rel)
        if physical is None:
            abort(403)
        if not os.path.exists(physical) and not active_file_exists(zone, rel):
            return rel
        # суффикс добавляем к базовому имени ровно один раз (без "name_x_y")
        candidate = f"{name}_{secrets.token_hex(4)}{ext}"
        while candidate in used_names:
            candidate = f"{name}_{secrets.token_hex(4)}{ext}"
        used_names.add(candidate)
    abort(500)


def upsert_file_record(owner, zone, rel_path, original_name, size):
    db = get_db()
    now_ms = time.time() * 1000
    row = db.execute(
        "SELECT id FROM files WHERE zone=? AND rel_path=? AND deleted_at IS NULL",
        (zone, rel_path),
    ).fetchone()
    if row:
        db.execute(
            "UPDATE files SET owner=?, original_name=?, size=?, created_ms=? WHERE id=?",
            (owner, original_name, size, now_ms, row["id"]),
        )
    else:
        db.execute(
            "INSERT INTO files (owner, zone, rel_path, original_name, size, created_ms)"
            " VALUES (?,?,?,?,?,?)",
            (owner, zone, rel_path, original_name, size, now_ms),
        )
    db.commit()


def increment_download(file_id):
    try:
        db = get_db()
        db.execute("UPDATE files SET download_count = download_count + 1 WHERE id=?", (file_id,))
        db.commit()
    except Exception:
        app.logger.exception("Failed to increment download count")


def file_to_dict(row):
    rel = row["rel_path"]
    zone = row["zone"]
    name = os.path.basename(rel)

    if zone == "public":
        url = f"/public/{quote(rel)}"
    else:
        parts = rel.split("/", 1)
        username = parts[0]
        filename = parts[1] if len(parts) > 1 else ""
        url = f"/private/{quote(username)}/{quote(filename)}"

    full_url = PUBLIC_BASE_URL + url

    share_full = None
    if row["share_token"] and row["share_expires_at"]:
        expires = parse_db_dt(row["share_expires_at"])
        if expires and expires > utcnow():
            share_full = f"{PUBLIC_BASE_URL}/share/{row['share_token']}"

    return {
        "id": row["id"],
        "owner": row["owner"],
        "zone": zone,
        "path": rel,
        "name": name,
        "size": row["size"] or 0,
        "created_at": row["created_at"] or "",
        "url": url,
        "full_url": full_url,
        "share_full": share_full,
        "download_count": row["download_count"] or 0,
        "can_delete": bool(session.get("is_admin") or row["owner"] == session.get("user")),
    }


# Допустимые варианты сортировки списков файлов (?sort=...)
SORT_OPTIONS = {
    # created_ms (мс, точность до миллисекунды) с фолбэком на created_at
    "new": ("COALESCE(created_ms, strftime('%s', created_at) * 1000) DESC", "Сначала новые"),
    "old": ("COALESCE(created_ms, strftime('%s', created_at) * 1000) ASC", "Сначала старые"),
    "name_asc": ("original_name COLLATE NOCASE ASC", "Имя А→Я"),
    "name_desc": ("original_name COLLATE NOCASE DESC", "Имя Я→А"),
    "size_desc": ("size DESC", "Размер ↓"),
    "size_asc": ("size ASC", "Размер ↑"),
}


def list_files(zone=None, owner=None, private_username=None, q=None, sort="new"):
    db = get_db()
    sql = "SELECT * FROM files WHERE deleted_at IS NULL"
    params = []

    if zone:
        sql += " AND zone = ?"
        params.append(zone)
    if owner:
        sql += " AND owner = ?"
        params.append(owner)
    if private_username:
        sql += " AND zone = 'private' AND rel_path LIKE ? ESCAPE '\\'"
        like_prefix = private_username.replace("\\", "\\\\").replace(
            "%", "\\%").replace("_", "\\_") + "/%"
        params.append(like_prefix)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        sql += (
            " AND (original_name LIKE ? ESCAPE '\\' OR rel_path LIKE ? ESCAPE '\\')"
        )
        like = f"%{escaped}%"
        params.extend([like, like])

    order = SORT_OPTIONS.get(sort, SORT_OPTIONS["new"])[0]
    # id — уникальный tie-breaker, чтобы пагинация/перерисовка были стабильны
    sql += f" ORDER BY {order}, id DESC LIMIT 1000"
    rows = db.execute(sql, params).fetchall()
    return [file_to_dict(r) for r in rows]


def list_trash(username=None, is_admin=False):
    """Список файлов в корзине (своих или всех для админа)."""
    db = get_db()
    sql = "SELECT * FROM files WHERE deleted_at IS NOT NULL"
    params = []
    if not is_admin:
        sql += " AND owner = ?"
        params.append(username)
    sql += " ORDER BY deleted_at DESC LIMIT 500"
    out = []
    for row in db.execute(sql, params).fetchall():
        deleted = parse_db_dt(row["deleted_at"])
        remaining_days = None
        if deleted:
            retention = effective_trash_retention_days()
            expires = deleted + timedelta(days=retention)
            remaining_days = max(0, (expires - utcnow()).days)
        out.append({
            "id": row["id"],
            "owner": row["owner"],
            "zone": row["zone"],
            "name": os.path.basename(row["rel_path"]),
            "path": row["rel_path"],
            "size": row["size"] or 0,
            "deleted_at": row["deleted_at"] or "",
            "remaining_days": remaining_days,
            "can_delete": bool(is_admin or row["owner"] == session.get("user")),
        })
    return out


def restore_file_from_trash(row):
    """Возвращает файл из корзины на исходное место (или под новым именем)."""
    trash_path = resolve_trash_path(row)
    if not trash_path or not os.path.isfile(trash_path):
        return False, "Физический файл в корзине не найден"

    base_dir = PRIVATE_DIR if row["zone"] == "private" else PUBLIC_DIR
    prefix = ""
    rel = row["rel_path"]
    if row["zone"] == "private":
        parts = rel.split("/", 1)
        prefix = parts[0]
    filename = os.path.basename(rel)

    # Если на месте уже другой файл — сохраняем под новым именем
    target_rel = rel
    if active_file_exists(row["zone"], rel) or \
            os.path.exists(resolve_storage_path(base_dir, rel) or ""):
        target_rel = unique_rel_path(base_dir, prefix, filename, row["zone"])

    target_path = resolve_storage_path(base_dir, target_rel)
    if target_path is None:
        return False, "Некорректный путь восстановления"

    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    shutil.move(trash_path, target_path)
    try:
        os.chmod(target_path, 0o640)
    except OSError:
        pass

    db = get_db()
    db.execute(
        "UPDATE files SET deleted_at=NULL, trash_path=NULL, rel_path=? WHERE id=?",
        (target_rel, row["id"]),
    )
    db.commit()
    return True, target_rel


def public_url(rel_path):
    return f"{PUBLIC_BASE_URL}/public/{quote(rel_path)}"


def private_url(username, filename):
    return f"{PUBLIC_BASE_URL}/private/{quote(username)}/{quote(filename)}"


# =====================================================================
# СОХРАНЕНИЕ ЗАГРУЗОК (потоком)
# =====================================================================
def save_upload_stream(stream, target_path, max_size=MAX_FILE_SIZE, quota_remaining=None):
    tmp_path = target_path + ".part"
    size = 0
    try:
        with open(tmp_path, "wb") as out:
            while True:
                chunk = stream.read(8 * 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_size:
                    raise UploadTooLarge()
                if quota_remaining is not None and size > quota_remaining:
                    raise QuotaExceeded()
                out.write(chunk)
        os.replace(tmp_path, target_path)
        try:
            os.chmod(target_path, 0o640)
        except OSError:
            pass
        return size
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


# =====================================================================
# КОРЗИНА
# =====================================================================
def move_file_record_to_trash(row):
    base_dir = PRIVATE_DIR if row["zone"] == "private" else PUBLIC_DIR
    path = resolve_storage_path(base_dir, row["rel_path"])
    base_name = secure_filename(os.path.basename(row["rel_path"]))
    trash_name = f"{row['id']}_{int(time.time())}_{base_name}"
    trash_path = os.path.join(TRASH_DIR, trash_name)

    if path and os.path.isfile(path):
        try:
            shutil.move(path, trash_path)
            try:
                os.chmod(trash_path, 0o640)
            except OSError:
                pass
        except Exception:
            app.logger.exception("Failed to move file to trash")
            return False

    db = get_db()
    db.execute(
        "UPDATE files SET deleted_at=?, trash_path=? WHERE id=?",
        (dbnow(), trash_name, row["id"]),
    )
    db.commit()
    return True


# =====================================================================
# ТОКЕНЫ БОЛЬШИХ ЗАГРУЗОК
# =====================================================================
def make_upload_token(username):
    exp = int(time.time()) + TOKEN_TTL
    msg = f"{username}:{exp}"
    sig = hmac.new(
        app.secret_key.encode(), msg.encode(), hashlib.sha256
    ).hexdigest()[:32]
    return f"{msg}:{sig}"


def check_upload_token(token):
    try:
        username, exp, sig = token.split(":")
        if int(exp) < time.time():
            return None
        msg = f"{username}:{exp}"
        expected = hmac.new(
            app.secret_key.encode(), msg.encode(), hashlib.sha256
        ).hexdigest()[:32]
        if hmac.compare_digest(sig, expected):
            return username
    except Exception:
        return None
    return None


# =====================================================================
# 🔐 SSH-СЕРТИФИКАТЫ
# =====================================================================
SSH_PRINCIPAL = os.environ.get("SSH_PRINCIPAL", "andrey")
SSH_HOST_HINT = os.environ.get(
    "SSH_HOST_HINT", "andrey-monoblock.tail098776.ts.net"
)
SSH_PORT = int(os.environ.get("SSH_PORT", "10000"))
SSH_SIGNER = "/usr/local/bin/goosko-ssh-sign.sh"
SSH_REVOKER = "/usr/local/bin/goosko-ssh-revoke.sh"
SSH_MIN_TTL, SSH_MAX_TTL = 5, 1440

# Бандлы приватных ключей: не храним их в памяти вечно.
# Потокобезопасный LRU с ограничением по количеству и времени жизни.
SSH_BUNDLE_TTL = 600          # 10 минут на скачивание
SSH_BUNDLE_MAX = 200          # максимум бандлов в памяти
SSH_BUNDLES = OrderedDict()
SSH_BUNDLES_LOCK = threading.Lock()


def ssh_bundles_put(token, priv, cert):
    with SSH_BUNDLES_LOCK:
        now = time.time()
        # выбрасываем протухшие
        expired = [k for k, v in SSH_BUNDLES.items() if now > v["expires"]]
        for k in expired:
            SSH_BUNDLES.pop(k, None)
        # ограничиваем размер
        while len(SSH_BUNDLES) >= SSH_BUNDLE_MAX:
            SSH_BUNDLES.popitem(last=False)
        SSH_BUNDLES[token] = {
            "priv": priv, "cert": cert, "expires": now + SSH_BUNDLE_TTL,
        }


def ssh_bundles_get(token):
    with SSH_BUNDLES_LOCK:
        b = SSH_BUNDLES.get(token)
        if not b or time.time() > b["expires"]:
            if b:
                SSH_BUNDLES.pop(token, None)
            return None
        return b


def ssh_bundles_cleanup():
    with SSH_BUNDLES_LOCK:
        now = time.time()
        for k in [k for k, v in SSH_BUNDLES.items() if now > v["expires"]]:
            SSH_BUNDLES.pop(k, None)


def ssh_sign(pubkey_text, ttl_minutes, identity):
    try:
        proc = subprocess.run(
            ["sudo", "-n", SSH_SIGNER, str(ttl_minutes), SSH_PRINCIPAL, identity],
            input=pubkey_text, capture_output=True, text=True, timeout=20,
        )
    except Exception:
        app.logger.exception("ssh sign subprocess failed")
        return None
    if proc.returncode != 0:
        app.logger.error("ssh sign failed: %s", proc.stderr.strip())
        return None
    cert = proc.stdout.strip()
    if not cert.split(" ")[0].endswith("-cert-v01@openssh.com"):
        return None
    return cert


def ssh_revoke_cert(cert_text):
    try:
        proc = subprocess.run(
            ["sudo", "-n", SSH_REVOKER],
            input=cert_text, capture_output=True, text=True, timeout=20,
        )
        return proc.returncode == 0
    except Exception:
        app.logger.exception("ssh revoke subprocess failed")
        return False


# =====================================================================
# БЕЗОПАСНЫЕ ЗАГОЛОВКИ
# =====================================================================
@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), display-capture=()"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    if request.is_secure and not IS_DEV:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

    # Запрещаем браузерам гадать о типе содержимого и встраивать нас во фреймы.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; connect-src 'self'; "
        "form-action 'self'; frame-src 'none'"
    )

    # MJPEG-превью камеры — картинка с того же origin (см. quick_camera_stream).
    if request.path == "/quick/stream.mjpg":
        response.headers["Content-Security-Policy"] = "default-src 'none'"

    # Файлы из хранилища не должны кэшироваться общими кэшами в приватной зоне.
    if request.path.startswith("/private/"):
        response.headers["Cache-Control"] = "private, no-store"

    return response


# =====================================================================
# ОШИБКИ
# =====================================================================
@app.errorhandler(404)
def error_404(e):
    return render_template(
        "error.html", code="404", icon="🔍",
        title="Страница не найдена",
        description="Похоже, вы заблудились. Такой страницы не существует.",
    ), 404


@app.errorhandler(403)
def error_403(e):
    return render_template(
        "error.html", code="403", icon="🚫",
        title="Доступ запрещён",
        description="У вас недостаточно прав для доступа к этой странице.",
    ), 403


@app.errorhandler(413)
def error_413(e):
    return render_template(
        "error.html", code="413", icon="📦",
        title="Файл слишком большой",
        description="Превышен максимальный размер загрузки.",
    ), 413


@app.errorhandler(429)
def error_429(e):
    return render_template(
        "error.html", code="429", icon="⏳",
        title="Слишком много запросов",
        description="Вы превысили лимит запросов. Попробуйте позже.",
    ), 429


@app.errorhandler(500)
def error_500(e):
    return render_template(
        "error.html", code="500", icon="🔥",
        title="Внутренняя ошибка сервера",
        description="Что-то пошло не так. Попробуйте обновить страницу.",
    ), 500


@app.errorhandler(CSRFError)
def csrf_error(e):
    return render_template(
        "error.html", code="400", icon="🧩",
        title="Ошибка CSRF",
        description="Обновите страницу и попробуйте снова.",
    ), 400


@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    app.logger.exception("Unhandled exception")
    return render_template(
        "error.html", code="500", icon="🐛",
        title="Непредвиденная ошибка",
        description="Произошла непредвиденная ошибка. Мы уже работаем над этим.",
    ), 500


# =====================================================================
# ОТДАЧА ФАЙЛОВ
# =====================================================================
def send_secure_file(path, attachment=False):
    filename = os.path.basename(path)
    response = send_file(
        path, as_attachment=attachment,
        download_name=filename, conditional=True,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    if attachment or not is_safe_public_filename(filename):
        response.headers["Content-Disposition"] = (
            f"attachment; filename*=UTF-8''{quote(filename)}"
        )
        response.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
    return response


def xaccel_private_response(rel_path, filename):
    response = app.response_class()
    response.headers["X-Accel-Redirect"] = f"/protected/{quote(rel_path)}"
    response.headers["Content-Type"] = "application/octet-stream"
    response.headers["Content-Disposition"] = (
        f"attachment; filename*=UTF-8''{quote(filename)}"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def xaccel_public_protected_response(rel_path, filename):
    response = app.response_class()
    response.headers["X-Accel-Redirect"] = f"/public-protected/{quote(rel_path)}"
    response.headers["Content-Type"] = "application/octet-stream"
    response.headers["Content-Disposition"] = (
        f"attachment; filename*=UTF-8''{quote(filename)}"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def send_file_response(path, attachment=False):
    """Отдача файла: Range-стриминг (настраивается) либо whole-file send_file."""
    if effective_stream_uploads():
        return send_streamable(
            path, download_name=os.path.basename(path), attachment=attachment)
    return send_secure_file(path, attachment=attachment)


# =====================================================================
# RANGE-ЗАПРОСЫ (перемотка видео/аудио в браузере)
# =====================================================================
def parse_range_header(range_header, file_size):
    """Разбирает HTTP Range ('bytes=a-b' / 'bytes=a-' / 'bytes=-N').

    Возвращает (start, end) включительно либо None. Невалидные диапазоны
    намеренно игнорируются — клиент получит весь файл (без 416).
    """
    if not range_header or not range_header.startswith("bytes="):
        return None
    spec = range_header[6:].split(",")[0].strip()
    if "-" not in spec:
        return None
    start_s, _, end_s = spec.partition("-")
    try:
        if start_s == "":
            if end_s == "":
                return None
            n = int(end_s)
            if n <= 0:
                return None
            start = max(0, file_size - n)
            end = file_size - 1
        else:
            start = int(start_s)
            end = int(end_s) if end_s else file_size - 1
    except ValueError:
        return None
    if start > end or start >= file_size:
        return None
    return start, min(end, file_size - 1)


def send_streamable(path, mimetype=None, download_name=None, attachment=False):
    """Отдача файла с поддержкой Range: 206 Partial Content для срезов."""
    file_size = os.path.getsize(path)
    if mimetype is None:
        import mimetypes
        mimetype = mimetypes.guess_type(path)[0] or "application/octet-stream"

    headers = {
        "Accept-Ranges": "bytes",
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
    }
    disposition = "attachment" if attachment else "inline"
    if download_name:
        headers["Content-Disposition"] = (
            f"{disposition}; filename*=UTF-8''{quote(download_name)}")
    if attachment or not is_safe_public_filename(os.path.basename(path)):
        # скачивание / потенциально опасный тип — изолируем от XSS
        headers["Content-Security-Policy"] = "sandbox; default-src 'none'"

    rng = parse_range_header(request.headers.get("Range"), file_size)
    if rng:
        start, end = rng
        length = end - start + 1

        def reader():
            with open(path, "rb") as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = f.read(min(64 * 1024, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    yield chunk

        headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        headers["Content-Length"] = str(length)
        return Response(reader(), status=206, mimetype=mimetype, headers=headers)

    def full_reader():
        with open(path, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                yield chunk

    headers["Content-Length"] = str(file_size)
    return Response(full_reader(), status=200, mimetype=mimetype, headers=headers)


# =====================================================================
# ГЛАВНАЯ
# =====================================================================
@app.route("/")
def index():
    if "user" in session:
        if session.get("is_admin"):
            db = get_db()
            users_rows = db.execute(
                "SELECT id, username, is_admin FROM users ORDER BY username"
            ).fetchall()
            usage_rows = db.execute(
                "SELECT owner, COALESCE(SUM(size), 0) AS total FROM files "
                "WHERE deleted_at IS NULL GROUP BY owner"
            ).fetchall()
            usage_map = {r["owner"]: r["total"] for r in usage_rows}
            users = [
                {
                    "id": r["id"],
                    "username": r["username"],
                    "is_admin": bool(r["is_admin"]),
                    "usage": usage_map.get(r["username"], 0),
                }
                for r in users_rows
            ]
            return render_template("admin.html", users=users)
        return render_template("user.html", user=session["user"])
    # Гость: показываем форму входа с сохранением цели перехода
    next_url = sanitize_next(request.args.get("next"))
    return render_template("login.html", next_url=next_url or "")


# =====================================================================
# ВХОД / ВЫХОД
# =====================================================================
# Фиктивные хеши: проверка всегда выполняется, даже если пользователя нет
# (защита от перечисления имён по времени ответа).
DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(32))

# Неудачные попытки входа: {ключ: [метки времени]}
_login_failures = {}
_login_failures_lock = threading.Lock()


def login_lock_key(username):
    return f"login:{(request.remote_addr or '?')}|{username.lower()}"


LOGIN_LOCK_WINDOW = 900       # окно наблюдения — 15 минут
LOGIN_LOCK_MAX_FAILURES = 10  # после этого блокируем


def login_is_locked(username):
    key = login_lock_key(username)
    with _login_failures_lock:
        failures = _login_failures.get(key)
        if not failures:
            return False
        recent = [t for t in failures if time.time() - t < LOGIN_LOCK_WINDOW]
        if recent:
            _login_failures[key] = recent
        else:
            _login_failures.pop(key, None)
        return len(recent) >= LOGIN_LOCK_MAX_FAILURES


def login_record_failure(username):
    key = login_lock_key(username)
    with _login_failures_lock:
        _login_failures.setdefault(key, []).append(time.time())
        # не даём словарю расти бесконечно
        if len(_login_failures) > 10000:
            cutoff = time.time() - LOGIN_LOCK_WINDOW
            for k in list(_login_failures):
                v = [t for t in _login_failures[k] if t >= cutoff]
                if v:
                    _login_failures[k] = v
                else:
                    _login_failures.pop(k, None)


@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    username = request.form.get("u", "").strip()
    password = request.form.get("p", "")

    if login_is_locked(username):
        audit("login_locked", username)
        flash("❌ Слишком много неудачных попыток. Подожди 15 минут.")
        return redirect("/")

    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    # Защита от тайминг-атак и перечисления пользователей:
    # всегда выполняем проверку хеша, даже если пользователя нет.
    hash_to_check = row["password"] if row else DUMMY_HASH
    password_ok = check_password_hash(hash_to_check, password)

    if row and password_ok:
        session.clear()
        session["user"] = row["username"]
        session["is_admin"] = bool(row["is_admin"])
        session.permanent = True
        with _login_failures_lock:
            _login_failures.pop(login_lock_key(username), None)
        audit("login_success", username)

        # Прозрачная миграция слабых хешей на scrypt
        if not row["password"].startswith("scrypt"):
            db = get_db()
            db.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (generate_password_hash(password), row["id"]),
            )
            db.commit()

        # Куда возвращаем пользователя?
        next_url = sanitize_next(request.form.get("next"))
        if not next_url:
            next_url = "/"
        return redirect(next_url)

    login_record_failure(username)
    audit("login_failed", username)
    flash("Неверный логин или пароль")
    return redirect("/")


def sanitize_next(url):
    """Разрешаем только внутренние относительные пути (защита от open redirect)."""
    if not url:
        return None
    if url.startswith("//") or not url.startswith("/"):
        return None
    if any(c in url for c in ("\r", "\n", "\\")):
        return None
    return url


@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("user")
    if username:
        audit("logout", username)
    session.clear()
    return redirect("/")


# =====================================================================
# АККАУНТ
# =====================================================================
@app.route("/account")
@login_required
def account():
    usage = get_user_usage(session["user"])
    quota = effective_user_quota()
    if session.get("is_admin"):
        percent = 100
    else:
        percent = min(100, int((usage / quota) * 100)) if quota else 100
    return render_template(
        "account.html", usage=usage, percent=percent, user_quota=quota,
    )


@app.route("/account/change-password", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def account_change_password():
    current_password = request.form.get("current", "")
    new_password = request.form.get("new", "")
    confirm_password = request.form.get("confirm", "")

    db = get_db()
    row = db.execute(
        "SELECT password FROM users WHERE username = ?", (session["user"],)
    ).fetchone()
    if not row or not check_password_hash(row["password"], current_password):
        audit("password_change_failed", session["user"])
        flash("❌ Текущий пароль неверный")
        return redirect(url_for("account"))

    problem = password_problem(new_password)
    if problem:
        flash(problem)
        return redirect(url_for("account"))

    if new_password != confirm_password:
        flash("❌ Пароли не совпадают")
        return redirect(url_for("account"))

    if new_password == current_password:
        flash("❌ Новый пароль совпадает с текущим")
        return redirect(url_for("account"))

    db.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (generate_password_hash(new_password), session["user"]),
    )
    db.commit()
    audit("password_changed", session["user"])
    session.clear()
    flash("✅ Пароль изменён. Войдите заново.")
    return redirect("/")


# =====================================================================
# ОБЛАКО: СТРАНИЦА
# =====================================================================
@app.route("/cloud")
@login_required
def cloud():
    q = request.args.get("q", "").strip()[:200]
    sort = request.args.get("sort", "new")
    if sort not in SORT_OPTIONS:
        sort = "new"
    username = session["user"]
    is_admin = session.get("is_admin", False)

    public_files = list_files(zone="public", q=q, sort=sort)
    if is_admin:
        private_files = list_files(zone="private", q=q, sort=sort)
    else:
        private_files = list_files(
            private_username=secure_filename(username), q=q, sort=sort
        )

    users = []
    if is_admin:
        rows = get_db().execute("SELECT username FROM users ORDER BY username").fetchall()
        users = [r["username"] for r in rows]

    usage = get_user_usage(username)
    quota = effective_user_quota()
    if is_admin:
        quota_percent = 100
    else:
        quota_percent = min(100, int((usage / quota) * 100)) if quota else 100

    return render_template(
        "cloud.html",
        public_files=public_files,
        private_files=private_files,
        users=users, q=q, usage=usage, quota_percent=quota_percent,
        user_quota=quota,
        max_file_size=effective_max_file_size(),
        sort=sort, sort_options=SORT_OPTIONS,
    )


# =====================================================================
# ОБЛАКО: КОРЗИНА
# =====================================================================
@app.route("/cloud/trash")
@login_required
def cloud_trash():
    is_admin = session.get("is_admin", False)
    files = list_trash(username=session["user"], is_admin=is_admin)
    return render_template(
        "trash.html", files=files,
        retention_days=effective_trash_retention_days(),
    )


@app.route("/cloud/restore/<int:file_id>", methods=["POST"])
@login_required
def cloud_restore(file_id):
    row = get_trash_file_by_id(file_id)
    if not row:
        flash("❌ Файл в корзине не найден")
        return redirect(url_for("cloud_trash"))
    if not (session.get("is_admin") or row["owner"] == session["user"]):
        flash("❌ Доступ запрещён")
        return redirect(url_for("cloud_trash"))
    ok, info = restore_file_from_trash(row)
    if ok:
        audit("restore", info)
        flash(f"♻️ Файл восстановлен: {os.path.basename(info)}")
    else:
        flash(f"❌ Не удалось восстановить файл: {info}")
    return redirect(url_for("cloud_trash"))


@app.route("/cloud/purge-trash", methods=["POST"])
@admin_required
def cloud_purge_trash():
    n = purge_trash_files()
    audit("trash_purged", f"{n} files")
    flash(f"🧹 Из корзины удалено файлов: {n}")
    return redirect(url_for("cloud_trash"))


# =====================================================================
# ОБЛАКО: ЗАГРУЗКА
# =====================================================================
def store_uploaded_file(user_row, zone, safe_name, stream_factory, owner=None):
    """Общая логика сохранения загруженного файла (для form- и JSON-API).

    stream_factory() возвращает открытый binary file-like объект.
    owner — владелец хранилища (для загрузки админом в private-зону другого
    пользователя); по умолчанию — сам загружающий.
    Возвращает dict с полями: name, size, url, full_url.
    Бросает ValueError с человекочитаемым сообщением при ошибках валидации.
    """
    username = user_row["username"]
    is_admin_user = bool(user_row["is_admin"])

    if zone not in ("public", "private"):
        raise ValueError("Неверная зона")
    if not safe_name:
        raise ValueError("Недопустимое имя файла")
    if zone == "public" and not is_admin_user and not is_safe_public_filename(safe_name):
        raise ValueError("Этот тип файла запрещён для публичной зоны обычным пользователям")

    max_size = effective_max_file_size()
    if zone == "public":
        if not valid_username(username):
            raise ValueError("Недопустимое имя пользователя")
        base_dir = PUBLIC_DIR
        if is_admin_user:
            prefix = ""
        else:
            prefix = secure_filename(username)
            ensure_dir(os.path.join(PUBLIC_DIR, prefix))
        owner = username
    else:
        if owner is None:
            owner = username
        if not valid_username(owner):
            raise ValueError("Недопустимое имя пользователя")
        base_dir = PRIVATE_DIR
        prefix = secure_filename(owner)
        get_user_private_dir(owner)  # гарантирует существование каталога

    remaining = None if is_admin_user else quota_remaining(owner)
    if remaining is not None and remaining <= 0:
        raise ValueError("Квота хранилища исчерпана")

    rel_path = unique_rel_path(base_dir, prefix, safe_name, zone)
    target_path = safe_storage_path(base_dir, rel_path)

    stream = stream_factory()
    try:
        size = save_upload_stream(
            stream, target_path,
            max_size=max_size, quota_remaining=remaining,
        )
    except UploadTooLarge:
        raise ValueError(f"Файл слишком большой (максимум {human_size(max_size)})")
    except QuotaExceeded:
        raise ValueError("Квота хранилища исчерпана")
    finally:
        try:
            stream.close()
        except Exception:
            pass

    upsert_file_record(owner, zone, rel_path, safe_name, size)

    if zone == "public":
        url = f"/public/{quote(rel_path)}"
    else:
        username_part, filename_part = rel_path.split("/", 1)
        url = f"/private/{quote(username_part)}/{quote(filename_part)}"

    return {
        "name": safe_name,
        "size": size,
        "url": url,
        "full_url": PUBLIC_BASE_URL + url,
    }


@app.route("/cloud/upload", methods=["POST"])
@login_required
def cloud_upload():
    if "file" not in request.files:
        flash("Файл не выбран")
        return redirect(url_for("cloud"))

    file = request.files["file"]
    if file.filename == "":
        flash("Файл не выбран")
        return redirect(url_for("cloud"))

    if request.content_length and request.content_length > effective_max_file_size():
        flash(f"❌ Файл слишком большой (максимум {human_size(effective_max_file_size())})")
        return redirect(url_for("cloud"))

    zone = request.form.get("zone", "private")
    if zone not in ("public", "private"):
        flash("❌ Неверная зона")
        return redirect(url_for("cloud"))

    is_admin = session.get("is_admin", False)

    if zone == "private" and is_admin:
        target_user = request.form.get("target_user", session["user"]).strip()
    else:
        target_user = session["user"]

    user_row = get_user_row(session["user"])
    if not user_row:
        flash("❌ Пользователь не найден")
        return redirect(url_for("cloud"))

    if zone == "private" and target_user != session["user"]:
        # админ может загружать в private-зону другого пользователя
        if not get_user_row(target_user):
            flash("❌ Пользователь не найден")
            return redirect(url_for("cloud"))

    safe_name = secure_filename(file.filename)

    try:
        info = store_uploaded_file(
            user_row, zone, safe_name, lambda: file.stream,
            owner=target_user if zone == "private" else None,
        )
    except ValueError as e:
        flash(f"❌ {e}")
        return redirect(url_for("cloud"))

    audit("upload", f"{zone}:{info['url']}")
    flash(f"✅ Файл загружен: {safe_name}")
    flash(f"🔗 Ссылка: {info['full_url']}")
    return redirect(url_for("cloud"))


@app.route("/cloud/upload-multi", methods=["POST"])
@login_required
@limiter.limit("120 per minute")
@csrf.exempt
def cloud_upload_multi():
    """Множественная загрузка через fetch (multipart с несколькими файлами).

    Ответ всегда JSON: {"ok": [...], "errors": [...]}, HTTP 200/400.
    """
    # CSRF: маршрут исключён из глобальной проверки (токен может приходить
    # в заголовке X-CSRFToken из fetch), поэтому проверяем вручную.
    if not _manual_csrf_ok():
        return jsonify(ok=[], errors=["Сессия устарела, обнови страницу"]), 400

    files = request.files.getlist("files") or request.files.getlist("file")
    if not files or all(f.filename == "" for f in files):
        return jsonify(ok=[], errors=["Файлы не выбраны"]), 400

    zone = request.form.get("zone", "private")
    user_row = get_user_row(session["user"])
    if not user_row:
        return jsonify(ok=[], errors=["Пользователь не найден"]), 400

    max_size = effective_max_file_size()
    ok_list, errors = [], []

    for f in files:
        if not f.filename:
            continue
        safe_name = secure_filename(f.filename)
        if not safe_name:
            errors.append(f"{f.filename}: недопустимое имя файла")
            continue
        try:
            # save_upload_stream читает file.stream напрямую; повторное
            # использование одного stream между файлами невозможно — Flask
            # даёт отдельный FileStorage на каждый файл, поэтому ок.
            info = store_uploaded_file(
                user_row, zone, safe_name, lambda f=f: f.stream
            )
        except ValueError as e:
            errors.append(f"{f.filename}: {e}")
            continue
        ok_list.append(info)

    if ok_list:
        audit(
            "upload_multi",
            "; ".join(f"{zone}:{i['url']}" for i in ok_list)[:500],
        )
    status = 200 if ok_list and not errors else (207 if ok_list else 400)
    return jsonify(ok=ok_list, errors=errors), status


# =====================================================================
# ОБЛАКО: ССЫЛКА ДЛЯ БОЛЬШОЙ ЗАГРУЗКИ
# =====================================================================
@app.route("/cloud/biglink")
@login_required
def cloud_biglink():
    token = make_upload_token(session["user"])
    url = f"{FUNNEL_HOST}/upload-big/{token}"
    audit("biglink_created", session["user"])
    flash(f"🎫 Ссылка для больших файлов (действует 1 час): {url}")
    return redirect(url_for("cloud"))


# =====================================================================
# БОЛЬШАЯ ЗАГРУЗКА ЧЕРЕЗ FUNNEL
# =====================================================================
@app.route("/upload-big/<token>", methods=["GET", "POST"])
@csrf.exempt
def upload_big(token):
    username = check_upload_token(token)
    if not username:
        return "❌ Ссылка недействительна или истекла", 403

    user_row = get_user_row(username)
    if not user_row:
        return "❌ Пользователь не найден", 403


    if request.method == "GET":
        return render_template("upload_big.html", token=token, user=username)

    if "file" not in request.files or request.files["file"].filename == "":
        return "❌ Файл не выбран", 400

    file = request.files["file"]
    zone = request.form.get("zone", "private")
    if zone not in ("public", "private"):
        return "❌ Неверная зона", 400

    safe_name = secure_filename(file.filename)
    if not safe_name:
        return "❌ Недопустимое имя файла", 400

    try:
        info = store_uploaded_file(user_row, zone, safe_name, lambda: file.stream)
    except ValueError as e:
        msg = str(e)
        # 413 — для квоты/размера, 400 — для остальных ошибок валидации
        status = 413 if ("Квота" in msg or "слишком большой" in msg) else 400
        return f"❌ {msg}", status

    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (username, action, details, ip) VALUES (?,?,?,?)",
            (username, "upload_big", f"{zone}:{info['url']}", request.remote_addr),
        )
        db.commit()
    except Exception:
        app.logger.exception("Audit failed for upload_big")

    return f"✅ Файл {safe_name} загружен", 200


# =====================================================================
# ОБЛАКО: ПОДЕЛИТЬСЯ ФАЙЛОМ
# =====================================================================
@app.route("/cloud/share/<int:file_id>", methods=["POST"])
@login_required
def share_file(file_id):
    row = get_active_file_by_id(file_id)
    if not row:
        flash("❌ Файл не найден")
        return redirect(url_for("cloud"))
    if not (session.get("is_admin") or row["owner"] == session["user"]):
        flash("❌ Доступ запрещён")
        return redirect(url_for("cloud"))

    token = secrets.token_urlsafe(24)
    expires = dbnow(utcnow() + timedelta(hours=effective_share_ttl_hours()))

    db = get_db()
    db.execute(
        "UPDATE files SET share_token=?, share_expires_at=? WHERE id=?",
        (token, expires, file_id),
    )
    db.commit()
    audit("share_created", row["rel_path"])
    flash(f"🔗 Временная ссылка: {PUBLIC_BASE_URL}/share/{token}")
    return redirect(url_for("cloud"))


# =====================================================================
# ОБЛАКО: УДАЛЕНИЕ В КОРЗИНУ
# =====================================================================
@app.route("/cloud/delete/<int:file_id>", methods=["POST"])
@login_required
def cloud_delete(file_id):
    row = get_active_file_by_id(file_id)
    if not row:
        flash("❌ Файл не найден")
        return redirect(url_for("cloud"))
    if not (session.get("is_admin") or row["owner"] == session["user"]):
        flash("❌ Доступ запрещён")
        return redirect(url_for("cloud"))
    if not move_file_record_to_trash(row):
        flash("❌ Не удалось переместить файл в корзину")
        return redirect(url_for("cloud"))
    audit("delete", row["rel_path"])
    flash("🗑️ Файл перемещён в корзину")
    return redirect(url_for("cloud"))


# =====================================================================
# ПРИВАТНЫЕ ФАЙЛЫ
# =====================================================================
@app.route("/private/<username>/<path:filename>")
@login_required
def private_file(username, filename):
    username = secure_filename(username)
    if not can_access_private(session["user"], session.get("is_admin", False), username):
        abort(403)
    rel_path = f"{username}/{filename}"
    path = safe_storage_path(PRIVATE_DIR, rel_path)
    if not os.path.isfile(path):
        abort(404)
    row = get_active_file_by_path("private", rel_path)
    if row:
        increment_download(row["id"])
    filename_base = os.path.basename(path)
    if USE_X_ACCEL:
        return xaccel_private_response(rel_path, filename_base)
    return send_file_response(path, attachment=True)


# =====================================================================
# ПУБЛИЧНЫЕ ФАЙЛЫ (fallback)
# =====================================================================
@app.route("/public/<path:rel_path>")
def public_file(rel_path):
    path = safe_storage_path(PUBLIC_DIR, rel_path)
    if not os.path.isfile(path):
        abort(404)
    row = get_active_file_by_path("public", rel_path)
    if row:
        increment_download(row["id"])
    attachment = not is_safe_public_filename(os.path.basename(path))
    return send_file_response(path, attachment=attachment)


# =====================================================================
# ВРЕМЕННЫЕ ССЫЛКИ
# =====================================================================
@app.route("/share/<token>")
def share_download(token):
    row = get_db().execute(
        "SELECT * FROM files WHERE share_token=? AND deleted_at IS NULL",
        (token,),
    ).fetchone()
    if not row:
        abort(404)
    expires = parse_db_dt(row["share_expires_at"])
    if not expires or expires <= utcnow():
        abort(404)
    base_dir = PRIVATE_DIR if row["zone"] == "private" else PUBLIC_DIR
    path = safe_storage_path(base_dir, row["rel_path"])
    if not os.path.isfile(path):
        abort(404)
    increment_download(row["id"])
    filename_base = os.path.basename(path)
    if USE_X_ACCEL:
        if row["zone"] == "private":
            return xaccel_private_response(row["rel_path"], filename_base)
        return xaccel_public_protected_response(row["rel_path"], filename_base)
    return send_file_response(path, attachment=True)


# =====================================================================
# АДМИН: СОЗДАНИЕ ПОЛЬЗОВАТЕЛЯ
# =====================================================================
@app.route("/admin/add", methods=["POST"])
@admin_required
def add_user():
    username = request.form.get("u", "").strip()
    password = request.form.get("p", "")
    is_admin = 1 if request.form.get("admin") else 0

    if not valid_username(username):
        flash("❌ Имя пользователя: 3-32 символа, только латиница, цифры, точка, дефис и _")
        return redirect(url_for("index"))

    problem = password_problem(password)
    if problem:
        flash(problem)
        return redirect(url_for("index"))

    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if row:
        flash("❌ Пользователь уже существует")
        return redirect(url_for("index"))

    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?,?,?)",
        (username, generate_password_hash(password), is_admin),
    )
    db.commit()
    audit("user_created", username)
    flash(f"✅ Пользователь {username} создан")
    return redirect(url_for("index"))


# =====================================================================
# АДМИН: УДАЛЕНИЕ ПОЛЬЗОВАТЕЛЯ
# =====================================================================
@app.route("/admin/del/<int:uid>", methods=["POST"])
@admin_required
def del_user(uid):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        flash("❌ Пользователь не найден")
        return redirect(url_for("index"))

    username = row["username"]
    if username == "admin":
        flash("❌ Нельзя удалить встроенного администратора")
        return redirect(url_for("index"))
    if username == session["user"]:
        flash("❌ Нельзя удалить самого себя")
        return redirect(url_for("index"))

    files = db.execute(
        "SELECT * FROM files WHERE deleted_at IS NULL AND (owner=? OR (zone='private' AND rel_path LIKE ?))",
        (username, f"{secure_filename(username)}/%"),
    ).fetchall()
    for file_row in files:
        move_file_record_to_trash(file_row)

    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    audit("user_deleted", username)
    flash(f"🗑️ Пользователь {username} удалён, его файлы перемещены в корзину")
    return redirect(url_for("index"))


# =====================================================================
# 💾 АДМИН: РЕЗЕРВНАЯ КОПИЯ (users.db + список файлов хранилища)
# =====================================================================
BACKUP_MAX_DB_BYTES = 200 * 1024 * 1024  # не отдаём дампы больше 200 МБ


@app.route("/admin/backup")
@admin_required
@limiter.limit("6 per hour")
def admin_backup():
    """Скачивание tar.gz: консистентный дамп SQLite + манифест хранилища.

    Сами файлы хранилища в архив не кладутся (могут быть ГБ) — вместо них
    manifest.txt с путями/размерами, чтобы сверить целостность после restore.
    Для полного бэкапа на сервере используйте deploy/backup.sh + rsync.
    """
    import sqlite3
    import tarfile
    import tempfile

    # читаем через globals(): тесты monkeypatch-ят BACKUP_MAX_DB_BYTES в app
    if os.path.getsize(DB) > globals()["BACKUP_MAX_DB_BYTES"]:
        abort(413, description="Слишком большая БД для скачивания из веба")

    fd, tmp_path = tempfile.mkstemp(suffix=".tar.gz", prefix="goosko-backup-")
    os.close(fd)
    try:
        dump_path = tmp_path + ".db"
        src = sqlite3.connect(DB, timeout=15)
        dst = sqlite3.connect(dump_path)
        try:
            src.backup(dst)  # горячий консистентный дамп (WAL-safe)
        finally:
            dst.close()
            src.close()

        # манифест хранилища
        manifest_lines = []
        for zone_dir in (PRIVATE_DIR, PUBLIC_DIR):
            for root, _dirs, files in os.walk(zone_dir):
                for fname in sorted(files):
                    full = os.path.join(root, fname)
                    try:
                        st = os.stat(full)
                    except OSError:
                        continue
                    rel = os.path.relpath(full, STORAGE_DIR)
                    manifest_lines.append(f"{rel}\t{st.st_size}\t{int(st.st_mtime)}")
        manifest_path = tmp_path + ".manifest.txt"
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write("\n".join(manifest_lines))

        stamp = utcnow().strftime("%Y%m%d_%H%M%S")
        out_name = f"goosko-backup_{stamp}.tar.gz"
        with tarfile.open(tmp_path, "w:gz") as tf:
            tf.add(dump_path, arcname="users.db")
            tf.add(manifest_path, arcname="storage_manifest.txt")
            readme = (
                "Goosko-online backup.\n"
                "Restore users.db поверх рабочей копии (сервис должен быть остановлен).\n"
                "storage_manifest.txt — список файлов хранилища (путь\\tразмер\\tmtime) "
                "для сверки; сами файлы копируйте с сервера (deploy/backup.sh).\n"
            ).encode("utf-8")
            info = tarfile.TarInfo("README.txt")
            info.size = len(readme)
            import io as _io
            tf.addfile(info, _io.BytesIO(readme))
        os.remove(dump_path)
        os.remove(manifest_path)

        audit("backup_downloaded", out_name)

        def _cleanup_tmp(path=tmp_path):
            try:
                os.remove(path)
            except OSError:
                pass
        atexit.register(_cleanup_tmp)  # файл нужен до отправки ответа

        return send_file(
            tmp_path, as_attachment=True, download_name=out_name,
            mimetype="application/gzip", conditional=False,
        )
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


# =====================================================================
# ⚙️ АДМИН: НАСТРОЙКИ СИСТЕМЫ
# =====================================================================
EDITABLE_SETTINGS = {
    # key: (метка, мин, макс, функция применения к человеку)
    "user_quota_bytes": ("Квота пользователя (байт)", 1024 ** 2, 1024 ** 5, False),
    "max_file_size_bytes": ("Макс. размер файла (байт)", 1024, 1024 ** 4, False),
    "share_ttl_hours": ("Время жизни ссылки (часы)", 1, 24 * 90, False),
    "trash_retention_days": ("Хранение в корзине (дни)", 0, 365, False),
    "camera_max_video_seconds": ("Макс. длина видео с камеры (сек)", 1, 600, False),
    "camera_preview_enabled": (
        "Живое превью камеры на стр. Быстрого доступа (1=вкл, 0=выкл)", 0, 1, True),
    "stream_uploads": (
        "Потоковая отдача файлов с Range (1=вкл, 0=выкл)", 0, 1, True),
}


@app.route("/admin/settings")
@admin_required
def admin_settings_page():
    rows = []
    for key, (label, lo, hi, is_flag) in EDITABLE_SETTINGS.items():
        value = get_int_setting(key, None)
        rows.append({
            "key": key, "label": label, "min": lo, "max": hi,
            "value": value if value is not None else lo,
            "is_flag": is_flag,
        })
    return render_template("settings.html", rows=rows)


@app.route("/admin/settings", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def admin_settings_save():
    db = get_db()
    changed = []
    errors = []
    for key, (label, lo, hi, _is_flag) in EDITABLE_SETTINGS.items():
        raw = request.form.get(key)
        if raw is None:
            continue
        try:
            value = int(raw)
        except ValueError:
            errors.append(f"{label}: не число")
            continue
        if not (lo <= value <= hi):
            errors.append(f"{label}: значение вне диапазона {lo}–{hi}")
            continue
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        changed.append(f"{key}={value}")
    db.commit()
    if changed:
        audit("settings_changed", "; ".join(changed))
    for err in errors:
        flash(f"❌ {err}")
    if changed and not errors:
        flash("✅ Настройки сохранены")
    elif not changed and not errors:
        flash("ℹ️ Изменений не найдено")
    return redirect(url_for("admin_settings_page"))


# =====================================================================
# 📜 АДМИН: ЖУРНАЛ СОБЫТИЙ
# =====================================================================
AUDIT_ACTIONS = [
    "", "login_failed", "login", "logout", "password_changed",
    "file_uploaded", "upload", "upload_multi", "file_big_uploaded", "upload_big",
    "file_deleted", "file_restored",
    "file_purged", "trash_purged", "share_created", "download",
    "user_added", "user_deleted", "settings_changed", "backup_downloaded",
    "ssh_cert_issued", "ssh_cert_revoked", "ssh_bundle_downloaded",
    "quick_photo", "quick_video", "quick_video_started", "quick_screenshot",
    "quick_media_deleted", "quick_media_purged", "power_action",
]


@app.route("/admin/log")
@admin_required
def admin_log_page():
    q = request.args.get("q", "").strip()[:100]
    action = request.args.get("action", "").strip()[:40]
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 50

    sql = "SELECT * FROM audit_log"
    conds, params = [], []
    if action in AUDIT_ACTIONS and action:
        conds.append("action = ?")
        params.append(action)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conds.append("(username LIKE ? ESCAPE '\\' OR details LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\')")
        like = f"%{escaped}%"
        params += [like, like, like]
    if conds:
        sql += " WHERE " + " AND ".join(conds)

    total = get_db().execute(
        "SELECT COUNT(*) FROM audit_log"
        + (" WHERE " + " AND ".join(conds) if conds else ""),
        params,
    ).fetchone()[0]
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    rows = get_db().execute(
        sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page],
    ).fetchall()

    return render_template(
        "log.html", rows=rows, q=q, action=action,
        page=page, pages=pages, total=total,
        actions=[a for a in AUDIT_ACTIONS if a],
    )


@app.route("/admin/log/export")
@admin_required
def admin_log_export():
    """Выгрузка журнала в CSV (для разбора инцидентов)."""
    import csv
    import io
    rows = get_db().execute(
        "SELECT created_at, username, action, details, ip "
        "FROM audit_log ORDER BY id DESC LIMIT 10000"
    ).fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["created_at", "username", "action", "details", "ip"])
    for r in rows:
        writer.writerow([r[0], r[1], r[2], r[3], r[4]])
    data = buf.getvalue().encode("utf-8-sig")  # BOM для Excel
    return Response(
        data, mimetype="text/csv",
        headers={
            "Content-Disposition":
                f"attachment; filename*=UTF-8''{quote('audit_log.csv')}",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.route("/admin/log/clear", methods=["POST"])
@admin_required
def admin_log_clear():
    """Очистка журнала старше N дней (по умолчанию 90)."""
    try:
        days = max(0, int(request.form.get("days", 90)))
    except ValueError:
        days = 90
    db = get_db()
    if days == 0:
        n = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        db.execute("DELETE FROM audit_log")
    else:
        n = db.execute(
            "SELECT COUNT(*) FROM audit_log "
            "WHERE created_at < datetime('now', ?)",
            (f"-{days} days",),
        ).fetchone()[0]
        db.execute(
            "DELETE FROM audit_log WHERE created_at < datetime('now', ?)",
            (f"-{days} days",),
        )
    db.commit()
    audit("log_cleared", f"удалено записей: {n} (старше {days} дн.)")
    flash(f"🧹 Журнал очищен: удалено {n} записей")
    return redirect(url_for("admin_log_page"))


# =====================================================================
# 🔐 SSH-СТРАНИЦА
# =====================================================================
@app.route("/ssh")
@admin_required
def ssh_page():
    certs = get_db().execute(
        "SELECT * FROM ssh_certs ORDER BY id DESC LIMIT 100"
    ).fetchall()
    return render_template(
        "ssh.html",
        certs=certs,
        now=dbnow(),
        principal=SSH_PRINCIPAL,
        host_hint=SSH_HOST_HINT,
        port=SSH_PORT,
        min_ttl=SSH_MIN_TTL,
        max_ttl=SSH_MAX_TTL,
    )


@app.route("/ssh/generate", methods=["POST"])
@admin_required
@limiter.limit("5 per hour")
def ssh_generate():
    try:
        ttl = int(request.form.get("ttl", 60))
    except (TypeError, ValueError):
        ttl = 0
    if not (SSH_MIN_TTL <= ttl <= SSH_MAX_TTL):
        flash(f"❌ TTL: от {SSH_MIN_TTL} до {SSH_MAX_TTL} минут")
        return redirect(url_for("ssh_page"))

    tmpdir = tempfile.mkdtemp(prefix="goosko-ssh-")
    try:
        key_path = os.path.join(tmpdir, "key")
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-f", key_path,
             "-N", "", "-C", f"goosko-temp-{session['user']}"],
            check=True, capture_output=True,
        )
        priv = open(key_path).read()
        pub = open(key_path + ".pub").read().strip()
    except Exception:
        flash("❌ Не удалось сгенерировать ключ")
        return redirect(url_for("ssh_page"))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    serial = int(time.time())
    identity = f"goosko-{session['user']}-{serial}"
    cert = ssh_sign(pub, ttl, identity)
    if not cert:
        flash("❌ Ошибка подписи (journalctl -u goosko-web)")
        return redirect(url_for("ssh_page"))

    expires = dbnow(utcnow() + timedelta(minutes=ttl))
    db = get_db()
    cur = db.execute(
        "INSERT INTO ssh_certs (serial, identity, principal, ttl_minutes, cert_text, created_by, expires_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (serial, identity, SSH_PRINCIPAL, ttl, cert, session["user"], expires),
    )
    db.commit()

    token = secrets.token_urlsafe(24)
    ssh_bundles_put(token, priv, cert)
    audit("ssh_cert_issued", f"id={cur.lastrowid} ttl={ttl}m")

    return render_template(
        "ssh_result.html",
        priv=priv, cert=cert, ttl=ttl, token=token,
        cert_id=cur.lastrowid, principal=SSH_PRINCIPAL,
        host_hint=SSH_HOST_HINT, port=SSH_PORT, expires=expires,
    )


@app.route("/ssh/download/<token>/<kind>")
@login_required
def ssh_download(token, kind):
    b = ssh_bundles_get(token)
    if not b:
        abort(404)
    # Скачал ключ/сертификат — бандл в памяти больше не нужен (одноразовый).
    with SSH_BUNDLES_LOCK:
        SSH_BUNDLES.pop(token, None)
    if kind == "key":
        data, name = b["priv"], "goosko_key"
    elif kind == "cert":
        data, name = b["cert"] + "\n", "goosko_key-cert.pub"
    elif kind == "bundle":
        data, name = b["priv"] + "\n" + b["cert"] + "\n", "goosko_key_bundle.txt"
    else:
        abort(404)
    resp = app.response_class(data, mimetype="text/plain")
    resp.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/ssh/revoke/<int:cert_id>", methods=["POST"])
@admin_required
def ssh_revoke(cert_id):
    db = get_db()
    row = db.execute(
        "SELECT * FROM ssh_certs WHERE id=? AND revoked_at IS NULL", (cert_id,)
    ).fetchone()
    if row and ssh_revoke_cert(row["cert_text"]):
        db.execute(
            "UPDATE ssh_certs SET revoked_at=? WHERE id=?", (dbnow(), cert_id)
        )
        db.commit()
        audit("ssh_cert_revoked", f"id={cert_id}")
        flash(f"✅ Сертификат #{cert_id} отозван")
    else:
        flash("❌ Не удалось отозвать сертификат")
    return redirect(url_for("ssh_page"))


# =====================================================================
# СЛУЖЕБНЫЙ РОУТ (для auth_request в Nginx)
# =====================================================================
@app.route("/check")
def check():
    if "user" in session:
        return "", 200
    return "", 401


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
