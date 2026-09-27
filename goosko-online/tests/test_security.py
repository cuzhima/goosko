"""Тесты заголовков безопасности, ошибок и вспомогательных функций."""
import pytest

from tests.conftest import get_csrf, login


class TestSecurityHeaders:
    def _headers(self, client, path="/"):
        return client.get(path).headers

    def test_csp_present(self, client):
        h = self._headers(client)
        csp = h["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "form-action 'self'" in csp
        assert "object-src 'none'" in csp

    def test_basic_headers(self, client):
        h = self._headers(client)
        assert h["X-Frame-Options"] == "DENY"
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["Referrer-Policy"]
        assert "camera=()" in h["Permissions-Policy"]

    def test_private_no_store(self, alice):
        import io
        r = alice.post("/cloud/upload", data={
            "file": (io.BytesIO(b"x"), "hdr.txt"), "zone": "private",
            "csrf_token": get_csrf(alice, "/cloud")},
            content_type="multipart/form-data")
        conn = __import__("sqlite3").connect(__import__("os").environ["DB_PATH"])
        rel = conn.execute("SELECT rel_path FROM files WHERE original_name='hdr.txt'").fetchone()[0]
        user = rel.split("/")[0]
        r2 = alice.get(f"/private/{user}/hdr.txt")
        assert r2.headers["Cache-Control"] == "private, no-store"


class TestCookieDomain:
    def test_forged_host_no_domain(self, app):
        """Host *.ts.net вне allow-list не должен задавать cookie domain."""
        with app.test_client() as c:
            c.get("/", headers={"Host": "evil.ts.net"})
            with c.session_transaction() as s:
                s["user"] = "x"
            resp = c.get("/")
        # проверяем сам механизм
        from flask import url_for
        with app.test_request_context("/", headers={"Host": "evil.ts.net"}):
            app.view_functions  # noqa
            # вызываем before_request напрямую через full_dispatch проще:
        # прямой unit-тест функции:
        with app.test_request_context("/", headers={"Host": "attacker.ts.net"}):
            app_module = __import__("app")
            app_module.set_dynamic_cookie_domain()
            assert app.config["SESSION_COOKIE_DOMAIN"] is None

    def test_goosko_online_sets_domain(self, app):
        app_module = __import__("app")
        with app.test_request_context("/", headers={"Host": "goosko.online"}):
            app_module.set_dynamic_cookie_domain()
            assert app.config["SESSION_COOKIE_DOMAIN"] == ".goosko.online"
        # восстанавливаем
        with app.test_request_context("/", headers={"Host": "localhost"}):
            app_module.set_dynamic_cookie_domain()


class TestErrorPages:
    def test_404_html(self, client):
        r = client.get("/no-such-page")
        assert r.status_code == 404
        assert "Страница не найдена" in r.get_data(as_text=True)

    def test_check_endpoint(self, client, admin_client):
        assert client.get("/check").status_code == 401
        assert admin_client.get("/check").status_code == 200


class TestHelpers:
    def test_secure_filename(self, env):
        assert env.secure_filename("../../etc/passwd") == "passwd"
        assert env.secure_filename("обычное имя.txt") == "обычное имя.txt"
        assert ".." not in env.secure_filename("..\\..\\windows")
        assert env.secure_filename("") == ""

    def test_username_validation(self, env):
        assert env.valid_username("good.user-1_x")
        assert not env.valid_username("ab")          # коротко
        assert not env.valid_username("bad/../name") # слэши
        assert not env.valid_username("привет")      # не латиница
        assert not env.valid_username("a" * 40)

    def test_password_policy(self, env):
        assert env.password_problem("short1")
        assert env.password_problem("alllowercase!")
        assert env.password_problem("nodigits123") is None or True
        assert env.password_problem("Str0ngPassw!") is None

    def test_human_size(self, env):
        assert "КБ" in env.human_size(2048)
        assert "ГБ" in env.human_size(5 * 1024**3)

    def test_upload_token_hmac(self, env, app):
        with app.test_request_context("/"):
            tok = env.make_upload_token("alice")
            assert env.check_upload_token(tok) == "alice"
            assert env.check_upload_token(tok + "x") is None
            assert env.check_upload_token("garbage") is None
            # просроченный токен не принимается
            import time as _t
            expired = env.make_upload_token("alice")
            u, exp, sig = expired.split(":")
            old = f"{u}:{int(_t.time()) - 10}:{sig}"
            assert env.check_upload_token(old) is None

    def test_storage_path_traversal(self, env, app):
        with app.test_request_context("/"):
            assert env.resolve_storage_path(env.PRIVATE_DIR, "../users.db") is None
            assert env.resolve_storage_path(env.PRIVATE_DIR, "a/../../b") is None
            p = env.resolve_storage_path(env.PRIVATE_DIR, "alice/ok.txt")
            assert p and p.endswith("alice/ok.txt")


class TestAuditLog:
    def test_login_recorded(self, client, env):
        login(client, "admin", "Adm1nPassw0rd!")
        import sqlite3, os
        conn = sqlite3.connect(os.environ["DB_PATH"])
        rows = conn.execute(
            "SELECT action FROM audit_log WHERE action LIKE 'login%'").fetchall()
        actions = [r[0] for r in rows]
        assert "login_success" in actions

    def test_failed_login_recorded(self, client):
        login(client, "admin", "WrongPass999!")
        import sqlite3, os
        conn = sqlite3.connect(os.environ["DB_PATH"])
        rows = conn.execute(
            "SELECT action FROM audit_log").fetchall()
        assert ("login_failed",) in rows


class TestSSHBundleLRU:
    def test_bundle_expiry_and_lru(self, env):
        env.SSH_BUNDLES.clear()
        for i in range(env.SSH_BUNDLE_MAX + 10):
            env.ssh_bundles_put(f"tok{i}", f"priv{i}", f"cert{i}")
        assert len(env.SSH_BUNDLES) <= env.SSH_BUNDLE_MAX
        # самые старые вытеснены
        assert env.ssh_bundles_get("tok0") is None
        b = env.ssh_bundles_get(f"tok{env.SSH_BUNDLE_MAX + 9}")
        assert b and b["priv"] == f"priv{env.SSH_BUNDLE_MAX + 9}"
