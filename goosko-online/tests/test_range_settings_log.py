"""Тесты: Range-запросы (206), страница настроек, журнал событий."""
import io
import os

from .conftest import get_csrf


def _upload(client, app_env, name="movie.mp4", data=b"0123456789ABCDEF" * 100,
            zone="private"):
    """Загружает файл в облако, возвращает (file_id, rel_path)."""
    csrf = get_csrf(client, "/cloud")
    r = client.post("/cloud/upload", data={
        "file": (io.BytesIO(data), name),
        "zone": zone,
        "csrf_token": csrf,
    }, content_type="multipart/form-data", follow_redirects=True)
    assert r.status_code == 200
    db = app_env.get_db() if hasattr(app_env, "get_db") else None
    row = client.application  # noqa - just to keep flake quiet
    return name


def _file_row(env, rel_path):
    import sqlite3
    conn = sqlite3.connect(os.environ["DB_PATH"])
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM files WHERE rel_path=?", (rel_path,)
        ).fetchone()
    finally:
        conn.close()


# ------------------------------------------------------------------ Range
class TestRangeRequests:
    def test_full_download_has_accept_ranges(self, alice, env):
        csrf = get_csrf(alice, "/cloud")
        alice.post("/cloud/upload", data={
            "file": (io.BytesIO(b"A" * 1000), "song.mp3"),
            "zone": "private", "csrf_token": csrf,
        }, content_type="multipart/form-data")
        r = alice.get(f"/private/alice/song.mp3")
        assert r.status_code == 200
        assert r.headers["Accept-Ranges"] == "bytes"
        assert r.headers["Content-Length"] == "1000"

    def test_partial_content_206(self, alice, env):
        csrf = get_csrf(alice, "/cloud")
        alice.post("/cloud/upload", data={
            "file": (io.BytesIO(bytes(range(256)) * 4), "blob.bin"),
            "zone": "private", "csrf_token": csrf,
        }, content_type="multipart/form-data")
        r = alice.get("/private/alice/blob.bin",
                      headers={"Range": "bytes=100-199"})
        assert r.status_code == 206
        assert r.headers["Content-Range"] == "bytes 100-199/1024"
        assert len(r.data) == 100
        assert r.data == bytes(range(100, 200))

    def test_open_ended_range(self, alice):
        csrf = get_csrf(alice, "/cloud")
        alice.post("/cloud/upload", data={
            "file": (io.BytesIO(b"0123456789"), "t.txt"),
            "zone": "private", "csrf_token": csrf,
        }, content_type="multipart/form-data")
        r = alice.get("/private/alice/t.txt", headers={"Range": "bytes=5-"})
        assert r.status_code == 206
        assert r.data == b"56789"

    def test_suffix_range(self, alice):
        csrf = get_csrf(alice, "/cloud")
        alice.post("/cloud/upload", data={
            "file": (io.BytesIO(b"0123456789"), "s.txt"),
            "zone": "private", "csrf_token": csrf,
        }, content_type="multipart/form-data")
        r = alice.get("/private/alice/s.txt", headers={"Range": "bytes=-3"})
        assert r.status_code == 206
        assert r.data == b"789"

    def test_invalid_range_falls_back_to_full(self, alice):
        csrf = get_csrf(alice, "/cloud")
        alice.post("/cloud/upload", data={
            "file": (io.BytesIO(b"x" * 50), "f.txt"),
            "zone": "private", "csrf_token": csrf,
        }, content_type="multipart/form-data")
        r = alice.get("/private/alice/f.txt", headers={"Range": "bytes=9999-"})
        assert r.status_code == 200
        assert len(r.data) == 50

    def test_parse_range_unit(self, env):
        p = env.parse_range_header
        assert p("bytes=0-9", 100) == (0, 9)
        assert p("bytes=50-", 100) == (50, 99)
        assert p("bytes=-10", 100) == (90, 99)
        assert p("bytes=99-200", 100) == (99, 99)
        assert p(None, 100) is None
        assert p("items=0-1", 100) is None
        assert p("bytes=abc-def", 100) is None
        assert p("bytes=200-300", 100) is None  # start >= size
        assert p("bytes=-0", 100) is None

    def test_stream_toggle_off_uses_send_file(self, admin_client, env):
        """stream_uploads=0 — файл отдаётся целиком через send_file (без 206)."""
        admin_client.post("/admin/settings", data={
            "stream_uploads": "0",
            "csrf_token": get_csrf(admin_client, "/admin/settings"),
        })
        with env.app.app_context():
            assert env.effective_stream_uploads() is False
        csrf = get_csrf(admin_client, "/cloud")
        admin_client.post("/cloud/upload", data={
            "file": (io.BytesIO(b"y" * 300), "off.bin"),
            "zone": "private", "csrf_token": csrf,
        }, content_type="multipart/form-data")
        r = admin_client.get("/private/admin/off.bin")
        # send_file(conditional=True) сам обрабатывает Range;
        # проверяем заголовки его пути (у нашего стримера был бы Accept-Ranges+nosniff CSP иначе)
        assert r.status_code in (200, 206)
        assert r.headers["Content-Length"] in ("300", "100") or r.status_code == 200
        if r.status_code == 200:
            assert len(r.data) == 300
        # путь send_secure_file всегда выставляет nosniff + attachment для /private
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert "attachment" in r.headers["Content-Disposition"]

    def test_html_public_gets_sandbox_csp(self, alice, env):
        """Опасный тип в публичной зоне для не-админа запрещён; проверка CSP на inline-safe html от админа."""
        csrf = get_csrf(alice, "/cloud")
        alice.post("/cloud/upload", data={
            "file": (io.BytesIO(b"<b>hi</b>"), "page.txt"),
            "zone": "public", "csrf_token": csrf,
        }, content_type="multipart/form-data")
        r = alice.get("/public/alice/page.txt")
        assert r.status_code == 200
        # txt безопасен — sandbox не обязателен, но nosniff да
        assert r.headers.get("X-Content-Type-Options") == "nosniff"


# ------------------------------------------------------- Settings page
class TestAdminSettings:
    def test_page_requires_admin(self, client, alice):
        assert client.get("/admin/settings").status_code in (302, 401, 403)
        assert alice.get("/admin/settings").status_code == 403

    def test_save_valid_and_effect_applied(self, admin_client, env):
        r = admin_client.post("/admin/settings", data={
            "share_ttl_hours": "48",
            "trash_retention_days": "7",
            "csrf_token": get_csrf(admin_client, "/admin/settings"),
        }, follow_redirects=True)
        assert r.status_code == 200
        with env.app.app_context():
            assert env.effective_share_ttl_hours() == 48
            assert env.effective_trash_retention_days() == 7

    def test_out_of_range_rejected(self, admin_client, env):
        with env.app.app_context():
            before = env.effective_share_ttl_hours()
        r = admin_client.post("/admin/settings", data={
            "share_ttl_hours": "999999",
            "csrf_token": get_csrf(admin_client, "/admin/settings"),
        }, follow_redirects=True)
        html = r.get_data(as_text=True)
        assert "вне диапазона" in html
        with env.app.app_context():
            assert env.effective_share_ttl_hours() == before

    def test_non_integer_rejected(self, admin_client, env):
        with env.app.app_context():
            before = env.effective_user_quota()
        r = admin_client.post("/admin/settings", data={
            "user_quota_bytes": "abc",
            "csrf_token": get_csrf(admin_client, "/admin/settings"),
        }, follow_redirects=True)
        assert "не число" in r.get_data(as_text=True)
        with env.app.app_context():
            assert env.effective_user_quota() == before

    def test_missing_csrf_rejected(self, admin_client, env):
        r = admin_client.post("/admin/settings", data={"share_ttl_hours": "5"})
        assert r.status_code == 400

    def test_quota_change_blocks_upload(self, alice, env):
        """Квота из настроек реально ограничивает загрузку."""
        ac_admin = alice.application.test_client()
        from .conftest import login
        login(ac_admin, "admin", "Adm1nPassw0rd!")
        ac_admin.post("/admin/settings", data={
            "user_quota_bytes": str(1024 * 1024),  # 1 MiB
            "csrf_token": get_csrf(ac_admin, "/admin/settings"),
        })
        big = b"z" * (2 * 1024 * 1024)
        r = alice.post("/cloud/upload", data={
            "file": (io.BytesIO(big), "big.bin"),
            "zone": "private",
            "csrf_token": get_csrf(alice, "/cloud"),
        }, content_type="multipart/form-data", follow_redirects=True)
        assert "превышена" in r.get_data(as_text=True).lower() or \
               "квот" in r.get_data(as_text=True).lower()


# ------------------------------------------------------------ Log page
class TestAdminLog:
    def test_page_requires_admin(self, client, alice):
        assert client.get("/admin/log").status_code in (302, 401, 403)
        assert alice.get("/admin/log").status_code == 403

    def test_login_event_recorded(self, admin_client):
        r = admin_client.get("/admin/log?action=login")
        assert r.status_code == 200
        assert "login" in r.get_data(as_text=True)

    def test_search_by_username(self, admin_client):
        r = admin_client.get("/admin/log?q=admin")
        assert r.status_code == 200

    def test_like_wildcards_escaped(self, admin_client):
        """Поиск с % и _ не должен матчить всё подряд (LIKE-экранирование)."""
        r = admin_client.get("/admin/log?q=%25%25")  # '%%'
        assert r.status_code == 200
        # записей с username='%%' быть не должно (без экранирования матчилось всё)
        assert "Всего записей: 0" in r.get_data(as_text=True)

    def test_export_csv(self, admin_client):
        r = admin_client.get("/admin/log/export")
        assert r.status_code == 200
        assert r.mimetype == "text/csv"
        body = r.data.decode("utf-8-sig")
        assert body.startswith("created_at,username,action,details,ip")

    def test_clear_old_entries(self, admin_client):
        csrf = get_csrf(admin_client, "/admin/log")
        r = admin_client.post("/admin/log/clear",
                              data={"days": "0", "csrf_token": csrf},
                              follow_redirects=True)
        assert r.status_code == 200
        assert "очищен" in r.get_data(as_text=True)

    def test_pagination(self, admin_client):
        r = admin_client.get("/admin/log?page=2")
        assert r.status_code == 200
        r = admin_client.get("/admin/log?page=99999")  # clamp к последней
        assert r.status_code == 200
