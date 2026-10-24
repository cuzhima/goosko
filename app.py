from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, send_file, send_from_directory, abort, g, Response,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import safe_join
from werkzeug.exceptions import HTTPException
from flask.sessions import SecureCookieSessionInterface
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import sqlite3
import functools
import threading
import json
import os
import secrets
import re
import unicodedata
import hashlib
import hmac
import time
import shutil
import subprocess
import subprocess
import tempfile
import mimetypes
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlsplit


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
def grant_nginx_access(path, default=False):
    try:
        subprocess.run(
            ["setfacl", "-m", "u:www-data:rX", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False,
        )
        if default and os.path.isdir(path):
            subprocess.run(
                ["setfacl", "-m", "d:u:www-data:rX", path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, check=False,
            )
    except Exception:
        pass


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o750)
    except OSError:
        pass
    grant_nginx_access(path, default=True)


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

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://goosko.online").rstrip("/")
PUBLIC_DOMAIN = ".goosko.online"  # домен cookie при входе через Cloudflare
try:
    _pd = urlsplit(PUBLIC_BASE_URL).hostname
    if _pd:
        PUBLIC_DOMAIN = "." + _pd
except (ValueError, AttributeError):
    pass

USE_X_ACCEL = os.environ.get("USE_X_ACCEL", "1") == "1"

DB = os.environ.get("DB_PATH", "users.db")

SYSTEM_STATUS_FILE = os.environ.get("SYSTEM_STATUS_FILE", "/run/goosko/system.json")
DISPLAY_HELPER = os.environ.get("DISPLAY_HELPER", "/usr/local/sbin/goosko-display")
POWER_HELPER = os.environ.get("POWER_HELPER", "/usr/local/sbin/goosko-power")
DISK_HELPER = os.environ.get("DISK_HELPER", "/usr/local/sbin/goosko-disk-tune")
FUNNEL_HELPER = os.environ.get("FUNNEL_HELPER", "/usr/local/sbin/goosko-funnel")
FUNNEL_STATE_FILE = os.environ.get("FUNNEL_STATE_FILE", "/run/goosko/funnel")
HELPER_TIMEOUT = int(os.environ.get("HELPER_TIMEOUT", "30"))


def _git_commit():
    """SHA текущего коммита (для /healthz и кеш-разделения sw.js)."""
    try:
        cwd = os.path.dirname(os.path.abspath(__file__))
        out = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=3, check=True,
        ).stdout.strip()
        return out or "unknown"
    except Exception:
        return "unknown"


GIT_SHA = _git_commit()


# =====================================================================
# FLASK APP
# =====================================================================
app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Нужно задать переменную окружения SECRET_KEY")

app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE,
    WTF_CSRF_TIME_LIMIT=3600,
    WTF_CSRF_SSL_STRICT=False,
    PREFERRED_URL_SCHEME="https",
)

# Поддержка Cloudflare и Tailscale Funnel
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

# =====================================================================
# ДИНАМИЧЕСКИЕ COOKIE (goosko.online + Tailscale Funnel + локальный IP)
# =====================================================================
class DynamicCookieSessionInterface(SecureCookieSessionInterface):
    """Домен и Secure считаются по реальному Host, без гонки app.config."""

    def get_cookie_domain(self, app):
        # Запрос пришёл через Cloudflare → Host может быть переписан (origin
        # rule). Cookie ставим на публичный домен, иначе браузер отбросит его.
        if request.headers.get("Cf-Ray"):
            return PUBLIC_DOMAIN
        try:
            host = request.host.split(":")[0].lower()
        except RuntimeError:
            return app.config.get("SESSION_COOKIE_DOMAIN")
        if host == "goosko.online" or host.endswith(".goosko.online"):
            return PUBLIC_DOMAIN
        if host.endswith(".ts.net"):
            return host
        return None

    def get_cookie_secure(self, app):
        try:
            if request.headers.get("Cf-Ray"):
                return True
            host = request.host.split(":")[0].lower()
            if host == "goosko.online" or host.endswith(".goosko.online"):
                return True
            if host.endswith(".ts.net"):
                return True
            return request.is_secure
        except RuntimeError:
            return app.config.get("SESSION_COOKIE_SECURE", True)


app.session_interface = DynamicCookieSessionInterface()

csrf = CSRFProtect(app)
def _limiter_storage():
    """Redis как единый storage лимитов; при недоступности — fallback на память."""
    try:
        import redis as redis_lib
        redis_lib.Redis(
            host="127.0.0.1", port=6379, db=0, socket_connect_timeout=1
        ).ping()
        return "redis://127.0.0.1:6379/0"
    except Exception:
        return "memory://"


limiter = Limiter(get_remote_address, app=app, storage_uri=_limiter_storage())


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


def is_safe_public_filename(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext not in UNSAFE_PUBLIC_EXTENSIONS


PREVIEW_EXTENSIONS = {
    "image": {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".avif"},
    "video": {".mp4", ".webm", ".ogv", ".mov", ".m4v"},
    "audio": {".mp3", ".wav", ".ogg", ".oga", ".flac", ".m4a", ".aac", ".opus"},
    "pdf": {".pdf"},
    "text": {".txt", ".md", ".markdown", ".log", ".csv", ".json", ".yaml", ".yml"},
}


def preview_kind(filename):
    ext = os.path.splitext(filename)[1].lower()
    for kind, extensions in PREVIEW_EXTENSIONS.items():
        if ext in extensions:
            return kind
    return None


FILE_KIND_GROUPS = {
    "image": PREVIEW_EXTENSIONS["image"],
    "video": PREVIEW_EXTENSIONS["video"],
    "audio": PREVIEW_EXTENSIONS["audio"],
    "text": PREVIEW_EXTENSIONS["text"],
    "document": {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".odt", ".ods", ".odp", ".rtf", ".epub",
    },
    "archive": {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".iso",
    },
}

FILE_KIND_LABELS = {
    "all": "Все файлы",
    "image": "Изображения",
    "video": "Видео",
    "audio": "Аудио",
    "text": "Текст и данные",
    "document": "Документы",
    "archive": "Архивы",
}

FILE_SORT_OPTIONS = {
    "date_desc": "Сначала новые",
    "date_asc": "Сначала старые",
    "name_asc": "Имя: А–Я",
    "name_desc": "Имя: Я–А",
    "size_desc": "Размер: больше",
    "size_asc": "Размер: меньше",
    "downloads_desc": "Популярные",
}

FILE_SORT_SQL = {
    "date_desc": "created_at DESC, id DESC",
    "date_asc": "created_at ASC, id ASC",
    "name_asc": "original_name COLLATE NOCASE ASC",
    "name_desc": "original_name COLLATE NOCASE DESC",
    "size_desc": "size DESC, id DESC",
    "size_asc": "size ASC, id ASC",
    "downloads_desc": "download_count DESC, id DESC",
}


def file_kind_filter(kind):
    extensions = FILE_KIND_GROUPS.get(kind)
    if not extensions:
        return "", []
    clauses = " OR ".join("lower(original_name) LIKE ?" for _ in extensions)
    params = [f"%{ext}" for ext in extensions]
    return "(" + clauses + ")", params


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

        CREATE UNIQUE INDEX IF NOT EXISTS idx_files_active
            ON files(zone, rel_path) WHERE deleted_at IS NULL;
        CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner);
        CREATE INDEX IF NOT EXISTS idx_files_zone ON files(zone);
    """)

    # Миграции старых БД
    for table, column, ctype in [
        ("files", "trash_path", "TEXT"),
        ("files", "share_token", "TEXT"),
        ("files", "share_expires_at", "TEXT"),
        ("files", "download_count", "INTEGER NOT NULL DEFAULT 0"),
    ]:
        add_column(conn, table, column, ctype)

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

    conn.commit()
    conn.close()


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
        "user_quota": USER_QUOTA,
        "max_file_size": MAX_FILE_SIZE,
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


AUDIT_ACTION_LABELS = {
    "login_success": "Вход",
    "login_failed": "Неудачный вход",
    "logout": "Выход",
    "password_changed": "Смена пароля",
    "upload": "Загрузка",
    "upload_big": "Большая загрузка",
    "biglink_created": "Ссылка для загрузки",
    "share_created": "Создана ссылка",
    "delete": "Удаление",
    "restore": "Восстановление",
    "purge": "Удаление навсегда",
    "trash_emptied": "Очистка корзины",
    "user_created": "Создан пользователь",
    "user_deleted": "Удалён пользователь",
    "ssh_cert_issued": "Выдан SSH-сертификат",
    "ssh_cert_revoked": "Отозван SSH-сертификат",
    "public_synced": "Синхронизация public",
    "system_action": "Системная команда",
}


# =====================================================================
# ДЕКОРАТОРЫ
# =====================================================================
def login_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("index"))
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
    return max(0, USER_QUOTA - get_user_usage(username))


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


def can_access_file_row(row):
    if row["zone"] == "public":
        return True
    username = row["rel_path"].split("/", 1)[0]
    return can_access_private(
        session.get("user"),
        session.get("is_admin", False),
        username,
    )


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
    candidate = filename
    for _ in range(100):
        rel = f"{prefix}/{candidate}" if prefix else candidate
        physical = resolve_storage_path(base_dir, rel)
        if physical is None:
            abort(403)
        if not os.path.exists(physical) and not active_file_exists(zone, rel):
            return rel
        candidate = f"{name}_{secrets.token_hex(4)}{ext}"
    abort(500)


def upsert_file_record(owner, zone, rel_path, original_name, size):
    db = get_db()
    row = db.execute(
        "SELECT id FROM files WHERE zone=? AND rel_path=? AND deleted_at IS NULL",
        (zone, rel_path),
    ).fetchone()
    if row:
        db.execute(
            "UPDATE files SET owner=?, original_name=?, size=? WHERE id=?",
            (owner, original_name, size, row["id"]),
        )
    else:
        db.execute(
            "INSERT INTO files (owner, zone, rel_path, original_name, size) VALUES (?,?,?,?,?)",
            (owner, zone, rel_path, original_name, size),
        )
    db.commit()


PUBLIC_SYNC_INTERVAL = 60
_public_sync_at = 0.0


def sync_public_files(force=False):
    global _public_sync_at

    now = time.monotonic()
    if not force and now - _public_sync_at < PUBLIC_SYNC_INTERVAL:
        return 0
    _public_sync_at = now

    db = get_db()
    usernames = {
        r["username"] for r in db.execute("SELECT username FROM users").fetchall()
    }
    added = 0

    for root, dirs, files in os.walk(PUBLIC_DIR, followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            if name.startswith(".") or name.endswith(".part"):
                continue
            path = os.path.join(root, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue

            rel_path = os.path.relpath(path, PUBLIC_DIR).replace(os.sep, "/")
            existing = get_active_file_by_path("public", rel_path)
            try:
                stat = os.stat(path)
            except OSError:
                continue

            if existing:
                if existing["size"] != stat.st_size:
                    db.execute(
                        "UPDATE files SET size=? WHERE id=?",
                        (stat.st_size, existing["id"]),
                    )
                    db.commit()
                continue

            first = rel_path.split("/", 1)[0]
            owner = first if "/" in rel_path and first in usernames else "admin"
            grant_nginx_access(path)
            created_at = dbnow(
                datetime.fromtimestamp(stat.st_mtime, timezone.utc)
            )
            try:
                db.execute(
                    "INSERT INTO files "
                    "(owner, zone, rel_path, original_name, size, created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (owner, "public", rel_path, name, stat.st_size, created_at),
                )
                db.commit()
                added += 1
            except sqlite3.IntegrityError:
                db.rollback()
            except Exception:
                db.rollback()
                app.logger.exception("Failed to sync public file")
    return added


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
        "preview_kind": preview_kind(name),
        "can_delete": bool(session.get("is_admin") or row["owner"] == session.get("user")),
    }


def list_files(zone=None, owner=None, private_username=None, q=None,
               kind=None, sort="date_desc"):
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
        sql += " AND zone = 'private' AND rel_path LIKE ?"
        params.append(private_username + "/%")
    if q:
        sql += " AND (original_name LIKE ? OR rel_path LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like])
    if kind:
        clause, kind_params = file_kind_filter(kind)
        if clause:
            sql += " AND " + clause
            params.extend(kind_params)

    order = FILE_SORT_SQL.get(sort, FILE_SORT_SQL["date_desc"])
    sql += f" ORDER BY {order} LIMIT 1000"
    rows = db.execute(sql, params).fetchall()
    return [file_to_dict(r) for r in rows]


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
        grant_nginx_access(target_path)
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
            grant_nginx_access(trash_path)
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


def can_manage_file(row):
    if session.get("is_admin"):
        return True
    return row["owner"] == session.get("user")


def list_trash_files(include_all=False):
    db = get_db()
    sql = "SELECT * FROM files WHERE deleted_at IS NOT NULL"
    params = []
    if not include_all:
        sql += " AND owner = ?"
        params.append(session.get("user"))
    sql += " ORDER BY deleted_at DESC LIMIT 1000"
    rows = db.execute(sql, params).fetchall()
    result = []
    for row in rows:
        item = file_to_dict(row)
        item["deleted_at"] = row["deleted_at"] or ""
        item["trash_name"] = row["trash_path"] or ""
        result.append(item)
    return result


def trash_physical_path(row):
    if not row["trash_path"]:
        return None
    return resolve_storage_path(TRASH_DIR, row["trash_path"])


def restore_file_record(row):
    base_dir = PRIVATE_DIR if row["zone"] == "private" else PUBLIC_DIR
    trash_file = trash_physical_path(row)
    if not trash_file or not os.path.isfile(trash_file):
        return None

    rel_path = row["rel_path"]
    candidate = resolve_storage_path(base_dir, rel_path)
    if candidate is None:
        return None

    if os.path.exists(candidate) or active_file_exists(row["zone"], rel_path):
        filename = os.path.basename(rel_path)
        prefix = rel_path.rsplit("/", 1)[0] if "/" in rel_path else ""
        rel_path = unique_rel_path(base_dir, prefix, filename, row["zone"])
        candidate = resolve_storage_path(base_dir, rel_path)
        if candidate is None:
            return None

    try:
        ensure_dir(os.path.dirname(candidate))
        shutil.move(trash_file, candidate)
        try:
            os.chmod(candidate, 0o640)
        except OSError:
            pass
        grant_nginx_access(candidate)
    except Exception:
        app.logger.exception("Failed to restore file from trash")
        return None

    db = get_db()
    db.execute(
        "UPDATE files SET deleted_at=NULL, trash_path=NULL, rel_path=? WHERE id=?",
        (rel_path, row["id"]),
    )
    db.commit()
    return rel_path


def purge_file_record(row):
    trash_file = trash_physical_path(row)
    if trash_file and os.path.isfile(trash_file):
        try:
            os.remove(trash_file)
        except OSError:
            app.logger.exception("Failed to remove trash file")
            return False
    db = get_db()
    db.execute("DELETE FROM files WHERE id=?", (row["id"],))
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
SSH_BUNDLES = {}


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
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    if request.is_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; media-src 'self'; object-src 'none'; "
        "worker-src 'self'; manifest-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'; connect-src 'self'"
    )
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
    try:
        app.logger.warning(
            "CSRF fail: reason=%r host=%s secure=%s cookies=%s "
            "session_keys=%s form_has_token=%s header_token=%s referer=%s",
            getattr(e, "description", ""), request.host, request.is_secure,
            list(request.cookies.keys()), list(session.keys()),
            "csrf_token" in request.form,
            request.headers.get("X-CSRFToken"),
            request.headers.get("Referer"),
        )
    except Exception:
        pass
    # Мягкий возврат: форма от другого хоста/устаревшая сессия — не тупик,
    # а новый логин на текущем хосте (отправим свежую session-куку).
    if request.method != "GET" and request.path not in ("/login",):
        flash("Сессия больше недействительна. Попробуйте ещё раз.")
        return redirect("/")
    flash("Время формы истекло. Попробуйте снова.")
    return redirect("/")


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


# =====================================================================
# ГЛАВНАЯ
# =====================================================================
def get_admin_stats():
    db = get_db()
    totals = db.execute(
        "SELECT COUNT(*) AS files_count, "
        "COALESCE(SUM(size), 0) AS total_size, "
        "COALESCE(SUM(download_count), 0) AS downloads "
        "FROM files WHERE deleted_at IS NULL"
    ).fetchone()
    trash_count = db.execute(
        "SELECT COUNT(*) FROM files WHERE deleted_at IS NOT NULL"
    ).fetchone()[0]
    uploads_24h = db.execute(
        "SELECT COUNT(*) FROM files WHERE deleted_at IS NULL "
        "AND created_at >= datetime('now', '-1 day')"
    ).fetchone()[0]
    events_24h = db.execute(
        "SELECT COUNT(*) FROM audit_log "
        "WHERE created_at >= datetime('now', '-1 day')"
    ).fetchone()[0]
    users_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    disk = shutil.disk_usage(STORAGE_DIR)
    recent_activity = db.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 8"
    ).fetchall()
    stats = {
        "users": users_count,
        "files": totals["files_count"],
        "size": totals["total_size"],
        "downloads": totals["downloads"],
        "trash": trash_count,
        "uploads_24h": uploads_24h,
        "events_24h": events_24h,
        "disk_total": disk.total,
        "disk_free": disk.free,
    }
    return stats, recent_activity


@app.route("/")
def index():
    if "user" in session:
        username = session["user"]
        if session.get("is_admin"):
            sync_public_files()
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

        usage = get_user_usage(username)
        percent = min(100, int((usage / USER_QUOTA) * 100)) if USER_QUOTA else 100
        recent_files = list_files(
            private_username=secure_filename(username), sort="date_desc"
        )[:5]
        return render_template(
            "user.html", user=username, usage=usage,
            quota_percent=percent, recent_files=recent_files,
        )
    return render_template("login.html")


# =====================================================================
# ВХОД / ВЫХОД
# =====================================================================
@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    username = request.form.get("u", "").strip()
    password = request.form.get("p", "")
    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row and check_password_hash(row["password"], password):
        session.clear()
        session["user"] = row["username"]
        session["is_admin"] = bool(row["is_admin"])
        session.permanent = True
        audit("login_success", username)
        return redirect("/")
    audit("login_failed", username)
    flash("Неверный логин или пароль")
    return redirect("/")


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
    if session.get("is_admin"):
        percent = 100
    else:
        percent = min(100, int((usage / USER_QUOTA) * 100)) if USER_QUOTA else 100
    return render_template("account.html", usage=usage, percent=percent)


@app.route("/account/change-password", methods=["POST"])
@login_required
def change_password():
    current_password = request.form.get("current", "")
    new_password = request.form.get("new", "")
    confirm_password = request.form.get("confirm", "")

    db = get_db()
    row = db.execute(
        "SELECT password FROM users WHERE username = ?", (session["user"],)
    ).fetchone()
    if not row or not check_password_hash(row["password"], current_password):
        flash("❌ Текущий пароль неверный")
        return redirect(url_for("account"))

    problem = password_problem(new_password)
    if problem:
        flash(problem)
        return redirect(url_for("account"))

    if new_password != confirm_password:
        flash("❌ Пароли не совпадают")
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
    q = request.args.get("q", "").strip()
    kind = request.args.get("kind", "all")
    if kind not in FILE_KIND_GROUPS:
        kind = "all"
    sort = request.args.get("sort", "date_desc")
    if sort not in FILE_SORT_SQL:
        sort = "date_desc"

    sync_public_files()

    username = session["user"]
    is_admin = session.get("is_admin", False)

    public_files = list_files(zone="public", q=q, kind=kind, sort=sort)
    if is_admin:
        private_files = list_files(zone="private", q=q, kind=kind, sort=sort)
    else:
        private_files = list_files(
            private_username=secure_filename(username),
            q=q, kind=kind, sort=sort,
        )

    users = []
    if is_admin:
        rows = get_db().execute("SELECT username FROM users ORDER BY username").fetchall()
        users = [r["username"] for r in rows]

    usage = get_user_usage(username)
    if is_admin:
        quota_percent = 100
    else:
        quota_percent = min(100, int((usage / USER_QUOTA) * 100)) if USER_QUOTA else 100

    return render_template(
        "cloud.html",
        public_files=public_files,
        private_files=private_files,
        users=users, q=q, usage=usage, quota_percent=quota_percent,
        kind=kind, sort=sort,
        kind_labels=FILE_KIND_LABELS, sort_options=FILE_SORT_OPTIONS,
    )


# =====================================================================
# ОБЛАКО: ЗАГРУЗКА
# =====================================================================
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

    if request.content_length and request.content_length > MAX_FILE_SIZE:
        flash(f"❌ Файл слишком большой (максимум {MAX_FILE_SIZE // (1024*1024)} МБ)")
        return redirect(url_for("cloud"))

    zone = request.form.get("zone", "private")
    if zone not in ("public", "private"):
        flash("❌ Неверная зона")
        return redirect(url_for("cloud"))

    is_admin = session.get("is_admin", False)

    if zone == "private":
        if is_admin:
            target_user = request.form.get("target_user", session["user"]).strip()
        else:
            target_user = session["user"]
    else:
        target_user = session["user"]

    if not valid_username(target_user):
        flash("❌ Недопустимое имя пользователя")
        return redirect(url_for("cloud"))

    target_row = get_user_row(target_user)
    if not target_row:
        flash("❌ Пользователь не найден")
        return redirect(url_for("cloud"))

    safe_name = secure_filename(file.filename)
    if not safe_name:
        flash("❌ Недопустимое имя файла")
        return redirect(url_for("cloud"))

    if zone == "public" and not is_admin and not is_safe_public_filename(safe_name):
        flash("❌ Этот тип файла запрещён для публичной зоны обычным пользователям")
        return redirect(url_for("cloud"))

    if zone == "public":
        base_dir = PUBLIC_DIR
        if is_admin:
            prefix = ""
            target_dir = PUBLIC_DIR
            owner = session["user"]
        else:
            prefix = secure_filename(session["user"])
            target_dir = os.path.join(PUBLIC_DIR, prefix)
            ensure_dir(target_dir)
            owner = session["user"]
    else:
        base_dir = PRIVATE_DIR
        prefix = secure_filename(target_user)
        target_dir = get_user_private_dir(target_user)
        owner = target_user

    owner_admin = is_admin_username(owner)
    remaining = None if owner_admin else quota_remaining(owner)

    if remaining is not None and remaining <= 0:
        flash("❌ Квота хранилища исчерпана")
        return redirect(url_for("cloud"))

    rel_path = unique_rel_path(base_dir, prefix, safe_name, zone)
    target_path = safe_storage_path(base_dir, rel_path)

    try:
        size = save_upload_stream(
            file.stream, target_path,
            max_size=MAX_FILE_SIZE, quota_remaining=remaining,
        )
    except UploadTooLarge:
        flash(f"❌ Файл слишком большой (максимум {MAX_FILE_SIZE // (1024*1024)} МБ)")
        return redirect(url_for("cloud"))
    except QuotaExceeded:
        flash("❌ Квота хранилища исчерпана")
        return redirect(url_for("cloud"))

    upsert_file_record(owner, zone, rel_path, safe_name, size)
    audit("upload", f"{zone}:{rel_path}")

    if zone == "public":
        link = public_url(rel_path)
    else:
        username_part, filename_part = rel_path.split("/", 1)
        link = private_url(username_part, filename_part)

    flash(f"✅ Файл загружен: {safe_name}")
    flash(f"🔗 Ссылка: {link}")
    return redirect(url_for("cloud"))


# =====================================================================
# ОБЛАЧНО: ССЫЛКА ДЛЯ БОЛЬШОЙ ЗАГРУЗКИ
# =====================================================================
@app.route("/cloud/biglink")
@login_required
def cloud_biglink():
    token = make_upload_token(session["user"])
    url = f"{PUBLIC_BASE_URL}/upload-big/{token}"
    audit("biglink_created", session["user"])

    funnel_on, funnel_base = funnel_state()
    if funnel_on and funnel_base:
        fast_url = funnel_base.rstrip("/") + f"/upload-big/{token}"
        flash(f"🎫 Через Cloudflare (до ~100 МБ): {url}")
        flash(f"🚀 Прямой канал без лимита CF (ts.net): {fast_url}")
    else:
        flash(
            f"🎫 Ссылка для больших файлов (действует 1 час): {url}. "
            "Для файлов >100 МБ включи Tailscale Funnel в разделе /system"
        )
    return redirect(url_for("cloud"))


# =====================================================================
# БОЛЬШАЯ ЗАГРУЗКА ПО ТОКЕНУ
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

    user_admin = bool(user_row["is_admin"])

    if request.method == "GET":
        return render_template(
            "upload_big.html",
            token=token,
            user=username,
            quota_remaining=None if user_admin else quota_remaining(username),
        )

    if "file" not in request.files or request.files["file"].filename == "":
        return "❌ Файл не выбран", 400

    if request.content_length and request.content_length > MAX_FILE_SIZE:
        return "❌ Файл больше 4 ГБ", 413

    file = request.files["file"]
    zone = request.form.get("zone", "private")
    if zone not in ("public", "private"):
        return "❌ Неверная зона", 400

    safe_name = secure_filename(file.filename)
    if not safe_name:
        return "❌ Недопустимое имя файла", 400

    if zone == "public" and not user_admin and not is_safe_public_filename(safe_name):
        return "❌ Этот тип файла запрещён для публичной зоны обычным пользователям", 400

    if zone == "private":
        base_dir = PRIVATE_DIR
        prefix = secure_filename(username)
        target_dir = get_user_private_dir(username)
        owner = username
    else:
        base_dir = PUBLIC_DIR
        if user_admin:
            prefix = ""
            target_dir = PUBLIC_DIR
        else:
            prefix = secure_filename(username)
            target_dir = os.path.join(PUBLIC_DIR, prefix)
            ensure_dir(target_dir)
        owner = username

    remaining = None if user_admin else quota_remaining(owner)
    if remaining is not None and remaining <= 0:
        return "❌ Квота хранилища исчерпана", 413

    rel_path = unique_rel_path(base_dir, prefix, safe_name, zone)
    target_path = safe_storage_path(base_dir, rel_path)

    try:
        size = save_upload_stream(
            file.stream, target_path,
            max_size=MAX_FILE_SIZE, quota_remaining=remaining,
        )
    except UploadTooLarge:
        return "❌ Файл больше 4 ГБ", 413
    except QuotaExceeded:
        return "❌ Квота хранилища исчерпана", 413

    upsert_file_record(owner, zone, rel_path, safe_name, size)
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (username, action, details, ip) VALUES (?,?,?,?)",
            (username, "upload_big", f"{zone}:{rel_path}", request.remote_addr),
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
    expires = dbnow(utcnow() + timedelta(hours=SHARE_TTL_HOURS))

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
# ОБЛАКО: КОРЗИНА
# =====================================================================
@app.route("/cloud/trash")
@login_required
def cloud_trash():
    files = list_trash_files(include_all=bool(session.get("is_admin")))
    return render_template("trash.html", files=files)


@app.route("/cloud/trash/restore/<int:file_id>", methods=["POST"])
@login_required
def restore_file(file_id):
    row = get_db().execute(
        "SELECT * FROM files WHERE id=? AND deleted_at IS NOT NULL", (file_id,)
    ).fetchone()
    if not row or not can_manage_file(row):
        flash("❌ Файл не найден")
        return redirect(url_for("cloud_trash"))
    rel_path = restore_file_record(row)
    if not rel_path:
        flash("❌ Не удалось восстановить файл")
        return redirect(url_for("cloud_trash"))
    audit("restore", rel_path)
    flash(f"♻️ Файл восстановлен: {os.path.basename(rel_path)}")
    return redirect(url_for("cloud_trash"))


@app.route("/cloud/trash/purge/<int:file_id>", methods=["POST"])
@login_required
def purge_file(file_id):
    row = get_db().execute(
        "SELECT * FROM files WHERE id=? AND deleted_at IS NOT NULL", (file_id,)
    ).fetchone()
    if not row or not can_manage_file(row):
        flash("❌ Файл не найден")
        return redirect(url_for("cloud_trash"))
    if not purge_file_record(row):
        flash("❌ Не удалось удалить файл")
        return redirect(url_for("cloud_trash"))
    audit("purge", row["rel_path"])
    flash("🔥 Файл удалён безвозвратно")
    return redirect(url_for("cloud_trash"))


@app.route("/cloud/trash/empty", methods=["POST"])
@login_required
def empty_trash():
    rows = get_db().execute(
        "SELECT * FROM files WHERE deleted_at IS NOT NULL" +
        ("" if session.get("is_admin") else " AND owner = ?"),
        () if session.get("is_admin") else (session.get("user"),),
    ).fetchall()
    count = 0
    for row in rows:
        if purge_file_record(row):
            count += 1
    audit("trash_emptied", f"count={count}")
    flash(f"🔥 Корзина очищена: {count} файл(ов)")
    return redirect(url_for("cloud_trash"))


# =====================================================================
# ОБЛАКО: ПРЕДПРОСМОТР И СКАЧИВАНИЕ
# =====================================================================
def preview_path_for(row):
    base_dir = PRIVATE_DIR if row["zone"] == "private" else PUBLIC_DIR
    path = safe_storage_path(base_dir, row["rel_path"])
    if not os.path.isfile(path):
        abort(404)
    return path


@app.route("/cloud/preview/<int:file_id>")
@login_required
def file_preview(file_id):
    row = get_active_file_by_id(file_id)
    if not row or not can_access_file_row(row):
        abort(404)
    kind = preview_kind(row["rel_path"])
    if not kind:
        flash("❌ Предпросмотр для этого файла недоступен")
        return redirect(url_for("cloud"))
    return render_template(
        "preview.html",
        file=file_to_dict(row),
        kind=kind,
        raw_url=url_for("file_raw", file_id=file_id),
        download_url=url_for("file_download", file_id=file_id),
    )


@app.route("/cloud/raw/<int:file_id>")
@login_required
def file_raw(file_id):
    row = get_active_file_by_id(file_id)
    if not row or not can_access_file_row(row):
        abort(404)
    kind = preview_kind(row["rel_path"])
    if not kind:
        abort(404)
    path = preview_path_for(row)
    name = os.path.basename(path)

    if kind == "text":
        mimetype = "text/plain; charset=utf-8"
    elif kind == "pdf":
        mimetype = "application/pdf"
    else:
        mimetype = mimetypes.guess_type(name)[0] or "application/octet-stream"

    response = send_file(
        path, mimetype=mimetype, download_name=name,
        conditional=True, as_attachment=False,
    )
    response.headers["Content-Disposition"] = (
        f"inline; filename*=UTF-8''{quote(name)}"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = (
        "private, max-age=300" if row["zone"] == "public" else "no-store"
    )
    return response


@app.route("/cloud/download/<int:file_id>")
@login_required
def file_download(file_id):
    row = get_active_file_by_id(file_id)
    if not row or not can_access_file_row(row):
        abort(404)
    increment_download(row["id"])
    name = os.path.basename(row["rel_path"])
    if row["zone"] == "private" and USE_X_ACCEL:
        return xaccel_private_response(row["rel_path"], name)
    path = preview_path_for(row)
    return send_secure_file(path, attachment=True)


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
    return send_secure_file(path, attachment=True)


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
    return send_secure_file(path, attachment=attachment)


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
    return send_secure_file(path, attachment=True)


# =====================================================================
# АДМИН: СТАТИСТИКА И СИНХРОНИЗАЦИЯ
# =====================================================================
@app.route("/admin/stats")
@admin_required
def admin_stats():
    sync_public_files()
    stats, recent_activity = get_admin_stats()
    return render_template(
        "admin_stats.html", stats=stats,
        recent_activity=recent_activity,
        action_labels=AUDIT_ACTION_LABELS,
    )


@app.route("/admin/sync-public", methods=["POST"])
@admin_required
def admin_sync_public():
    added = sync_public_files(force=True)
    audit("public_synced", f"added={added}")
    flash(f"✅ Синхронизация завершена. Добавлено файлов: {added}")
    return redirect(url_for("admin_stats"))


# =====================================================================
# АДМИН: ЖУРНАЛ АКТИВНОСТИ
# =====================================================================
@app.route("/admin/activity")
@admin_required
def admin_activity():
    action = request.args.get("action", "").strip()
    username = request.args.get("user", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    if page < 1:
        page = 1
    per_page = 50

    where = []
    params = []
    if action:
        where.append("action = ?")
        params.append(action)
    if username:
        where.append("username = ?")
        params.append(username)
    clause = " AND ".join(where) if where else "1=1"

    db = get_db()
    total = db.execute(
        f"SELECT COUNT(*) FROM audit_log WHERE {clause}", params
    ).fetchone()[0]
    pages = max(1, (total + per_page - 1) // per_page)
    if page > pages:
        page = pages
    rows = db.execute(
        f"SELECT * FROM audit_log WHERE {clause} "
        "ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page],
    ).fetchall()
    actions = [
        r["action"] for r in db.execute(
            "SELECT DISTINCT action FROM audit_log ORDER BY action"
        ).fetchall()
    ]
    usernames = [
        r["username"] for r in db.execute(
            "SELECT DISTINCT username FROM audit_log "
            "WHERE username IS NOT NULL ORDER BY username"
        ).fetchall()
    ]

    return render_template(
        "activity.html", rows=rows, action=action, username=username,
        actions=actions, usernames=usernames, page=page, pages=pages,
        total=total, per_page=per_page,
        action_labels=AUDIT_ACTION_LABELS,
    )


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
    SSH_BUNDLES[token] = {
        "priv": priv, "cert": cert, "expires": time.time() + 600,
    }
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
    b = SSH_BUNDLES.get(token)
    if not b or time.time() > b["expires"]:
        abort(404)
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
# СИСТЕМА: СТАТУС, ЭКРАН, ПИТАНИЕ, ДИСК, ТЕРМОКОНТРОЛЬ
# =====================================================================
SYSTEM_ACTIONS = {
    "display_on": (DISPLAY_HELPER, ["on"]),
    "display_off": (DISPLAY_HELPER, ["off"]),
    "power_eco": (POWER_HELPER, ["eco"]),
    "power_balanced": (POWER_HELPER, ["balanced"]),
    "power_performance": (POWER_HELPER, ["performance"]),
    "disk_tune": (DISK_HELPER, []),
    "funnel_on": (FUNNEL_HELPER, ["start"]),
    "funnel_off": (FUNNEL_HELPER, ["stop"]),
}


def funnel_state():
    """(on, url) из state-файла, который пишет goosko-funnel."""
    value = _read_text(FUNNEL_STATE_FILE)
    if not value:
        return False, None
    parts = value.split()
    if parts[0] != "on" or len(parts) < 2:
        return False, None
    return True, parts[1]


def _read_text(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return default


def _read_int(path, default=None):
    value = _read_text(path)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _json_response(payload, status=200):
    response = Response(
        json.dumps(payload, ensure_ascii=False),
        status=status,
        mimetype="application/json",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _cpu_model():
    for line in (_read_text("/proc/cpuinfo", "") or "").splitlines():
        if line.lower().startswith("model name"):
            return line.split(":", 1)[1].strip()
    return None


def _cpu_temp():
    try:
        entries = os.listdir("/sys/class/hwmon")
    except OSError:
        entries = []
    for entry in entries:
        base = os.path.join("/sys/class/hwmon", entry)
        if _read_text(os.path.join(base, "name")) != "coretemp":
            continue
        value = _read_int(os.path.join(base, "temp1_input"))
        if value is not None:
            return round(value / 1000.0, 1)
    try:
        zones = os.listdir("/sys/class/thermal")
    except OSError:
        zones = []
    for zone in zones:
        if not zone.startswith("thermal_zone"):
            continue
        base = os.path.join("/sys/class/thermal", zone)
        if _read_text(os.path.join(base, "type")) not in ("x86_pkg_temp", "cpu-thermal"):
            continue
        value = _read_int(os.path.join(base, "temp"))
        if value is not None:
            return round(value / 1000.0, 1)
    return None


def _backlight_state():
    try:
        names = sorted(os.listdir("/sys/class/backlight"))
    except OSError:
        names = []
    devices = []
    for name in names:
        base = os.path.join("/sys/class/backlight", name)
        cur = _read_int(os.path.join(base, "brightness"))
        mx = _read_int(os.path.join(base, "max_brightness"))
        if cur is None or not mx:
            continue
        devices.append({
            "name": name,
            "brightness": cur,
            "max": mx,
            "percent": max(0, min(100, round(cur * 100 / mx))),
        })
    return devices


def _service_active(unit):
    try:
        result = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return (result.stdout or "").strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _freq_mhz(path):
    value = _read_int(path)
    return round(value / 1000.0) if value else None


SYSTEM_STATUS_CACHE_TTL = 5.0  # секунд; /system/status опрашивается каждые 10с
_status_cache_lock = threading.Lock()
_status_cache: dict = {"t": 0.0, "data": None}


def get_system_status():
    now = time.time()
    with _status_cache_lock:
        if _status_cache["data"] is not None and now - _status_cache["t"] < SYSTEM_STATUS_CACHE_TTL:
            return _status_cache["data"]

    data = _build_system_status()
    with _status_cache_lock:
        _status_cache["t"] = time.time()
        _status_cache["data"] = data
    return data


def _build_system_status():
    saved = _read_json(SYSTEM_STATUS_FILE)
    cpu = dict(saved.get("cpu") or {})
    disk = dict(saved.get("disk") or {})
    display = dict(saved.get("display") or {})
    funnel_on, funnel_url = funnel_state()

    cpu["model"] = cpu.get("model") or _cpu_model()
    cpu["temp"] = _cpu_temp()
    try:
        cpu["load1"] = round(os.getloadavg()[0], 2)
    except OSError:
        cpu["load1"] = None
    cpu["governor"] = _read_text(
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
    )
    cpu["epp"] = _read_text(
        "/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference"
    )
    cpu["freq_mhz"] = _freq_mhz(
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"
    )
    cpu["max_mhz"] = _freq_mhz(
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"
    )
    cpu["no_turbo"] = _read_int(
        "/sys/devices/system/cpu/intel_pstate/no_turbo"
    )
    cpu["profile"] = cpu.get("profile") or _read_text(
        "/etc/goosko/power_profile", "unknown"
    )
    cpu["thermal"] = cpu.get("thermal") or "unknown"

    display["lightdm"] = _service_active("lightdm")
    display["backlight"] = _backlight_state()

    block = os.path.basename(disk.get("dev") or "/dev/sda")
    disk["dev"] = disk.get("dev") or "/dev/sda"
    disk["model"] = disk.get("model") or _read_text(
        f"/sys/block/{block}/device/model"
    )
    disk["rotational"] = (
        _read_text(f"/sys/block/{block}/queue/rotational") == "1"
    )
    scheduler = _read_text(f"/sys/block/{block}/queue/scheduler", "") or ""
    match = re.search(r"\[([^\]]+)\]", scheduler)
    disk["scheduler"] = (
        match.group(1) if match
        else (scheduler.split()[-1] if scheduler else None)
    )

    updated = saved.get("updated")
    try:
        stale = not updated or (time.time() - float(updated) > 180)
    except (TypeError, ValueError):
        stale = True

    return {
        "cpu": cpu,
        "disk": disk,
        "display": display,
        "config": saved.get("config") or {},
        "updated": updated,
        "stale": stale,
        "server_time": int(time.time()),
        "funnel": {"on": funnel_on, "url": funnel_url},
        "helpers": {
            "display": os.path.exists(DISPLAY_HELPER),
            "power": os.path.exists(POWER_HELPER),
            "disk": os.path.exists(DISK_HELPER),
            "funnel": os.path.exists(FUNNEL_HELPER),
        },
    }


def _run_system_helper(argv):
    if not os.path.exists(argv[0]):
        return False, f"Не установлен помощник {argv[0]}. Запустите system/install.sh"
    try:
        result = subprocess.run(
            ["sudo", "-n", *argv],
            capture_output=True, text=True,
            timeout=HELPER_TIMEOUT, check=False,
        )
    except FileNotFoundError:
        return False, "sudo не найден"
    except subprocess.TimeoutExpired:
        return False, "Команда не завершилась за отведённое время"
    output = (result.stdout or "").strip()
    error = (result.stderr or "").strip()
    if result.returncode == 0:
        return True, output or "Готово"
    return False, error or output or f"Код возврата {result.returncode}"


@app.route("/system")
@admin_required
def system_page():
    return render_template("system.html", status=get_system_status())


@app.route("/system/status")
@admin_required
def system_status():
    return _json_response(get_system_status())


@app.route("/system/action", methods=["POST"])
@admin_required
def system_action():
    payload = request.get_json(silent=True) or request.form
    action = str(payload.get("action", "")).strip()

    if action == "brightness":
        try:
            value = int(payload.get("value", 100))
        except (TypeError, ValueError):
            return _json_response(
                {"ok": False, "message": "Некорректная яркость"}, 400
            )
        if not 0 <= value <= 100:
            return _json_response(
                {"ok": False, "message": "Яркость должна быть 0–100%"}, 400
            )
        argv = [DISPLAY_HELPER, "brightness", str(value)]
    else:
        item = SYSTEM_ACTIONS.get(action)
        if not item:
            return _json_response(
                {"ok": False, "message": "Неизвестное действие"}, 400
            )
        argv = [item[0], *item[1]]

    ok, message = _run_system_helper(argv)
    audit("system_action", f"{action}: {message[:180]}")
    if ok:
        # helpers меняют состояние (экран, профиль, funnel) — кеш не нужен
        with _status_cache_lock:
            _status_cache["t"] = 0.0
            _status_cache["data"] = None
    return _json_response(
        {"ok": ok, "message": message}, 200 if ok else 500
    )


# =====================================================================
# СЛУЖЕБНЫЙ РОУТ (для auth_request в Nginx)
# =====================================================================
@app.route("/healthz")
def healthz():
    """Публичный healthcheck: nginx/мониторинг проверяют живость."""
    return _json_response({"ok": True, "sha": GIT_SHA}, 200)


@app.route("/check")
def check():
    if "user" in session:
        return "", 200
    return "", 401


# =====================================================================
# PWA
# =====================================================================
@app.route("/manifest.webmanifest")
def web_manifest():
    response = send_from_directory(
        app.static_folder, "manifest.webmanifest",
        mimetype="application/manifest+json",
    )
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@app.route("/sw.js")
def service_worker():
    """sw.js с версией кеша по SHA коммита: обновление PWA после деплоя."""
    sw_path = os.path.join(app.static_folder, "sw.js")
    try:
        with open(sw_path, "r", encoding="utf-8") as f:
            sw_content = f.read()
    except OSError:
        return "console.error('sw.js not found');", 404
    sw_content = re.sub(
        r'(CACHE_NAME\s*=\s*)"[^"]*"',
        r'\1"goosko-' + GIT_SHA + '"',
        sw_content,
        count=1,
    )
    response = app.response_class(sw_content, mimetype="application/javascript")
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response


@app.route("/offline")
def offline_page():
    return render_template("offline.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
