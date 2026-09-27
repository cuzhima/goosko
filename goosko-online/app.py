from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, send_file, abort, g, Response,
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
import os
import secrets
import re
import unicodedata
import hashlib
import hmac
import time
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from urllib.parse import quote


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

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")


# =====================================================================
# ДИНАМИЧЕСКИЙ COOKIE_DOMAIN (для goosko.online + Tailscale Funnel)
# =====================================================================
@app.before_request
def set_dynamic_cookie_domain():
    host = request.host.split(":")[0]
    if host == "goosko.online" or host.endswith(".goosko.online"):
        app.config["SESSION_COOKIE_DOMAIN"] = ".goosko.online"
    elif host.endswith(".ts.net"):
        app.config["SESSION_COOKIE_DOMAIN"] = host
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


def is_safe_public_filename(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext not in UNSAFE_PUBLIC_EXTENSIONS


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


def list_files(zone=None, owner=None, private_username=None, q=None):
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

    sql += " ORDER BY created_at DESC LIMIT 1000"
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
        "img-src 'self' data:; object-src 'none'; "
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
    username = session["user"]
    is_admin = session.get("is_admin", False)

    public_files = list_files(zone="public", q=q)
    if is_admin:
        private_files = list_files(zone="private", q=q)
    else:
        private_files = list_files(private_username=secure_filename(username), q=q)

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

    user_admin = bool(user_row["is_admin"])

    if request.method == "GET":
        return render_template("upload_big.html", token=token, user=username)

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
        host=SSH_HOST_HINT,
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
        host=SSH_HOST_HINT, port=SSH_PORT, expires=expires,
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
# СЛУЖЕБНЫЙ РОУТ (для auth_request в Nginx)
# =====================================================================
@app.route("/check")
def check():
    if "user" in session:
        return "", 200
    return "", 401


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
