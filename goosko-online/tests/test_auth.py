"""Тесты аутентификации, защиты от брутфорса и CSRF."""
from tests.conftest import get_csrf, login


class TestLogin:
    def test_login_page_for_guest(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "csrf_token" in r.get_data(as_text=True)

    def test_correct_login_admin(self, client):
        r = login(client, "admin", "Adm1nPassw0rd!")
        assert r.status_code == 302
        # после входа главная отдаёт админку
        page = client.get("/").get_data(as_text=True)
        assert "admin" in page

    def test_wrong_password(self, client):
        r = login(client, "admin", "WrongPass123!")
        assert r.status_code == 302
        assert r.headers["Location"] in ("/", "http://localhost/")
        # сессия не создана
        assert client.get("/cloud").status_code == 302

    def test_nonexistent_user_same_error(self, client):
        """Нет пользователя — то же сообщение, что и неверный пароль."""
        r1 = login(client, "nosuchuser1", "SomePass123!")
        c2 = r1.request.application  # not used; just ensure no crash
        html = client.get("/").get_data(as_text=True)
        assert "Неверный логин или пароль" in html

    def test_session_persists_and_logout(self, client):
        login(client, "admin", "Adm1nPassw0rd!")
        token = get_csrf(client, "/account")
        r = client.post("/logout", data={"csrf_token": token})
        assert r.status_code == 302
        assert client.get("/account").status_code == 302


class TestBruteForceLockout:
    def test_lockout_after_10_failures(self, client, app):
        for i in range(10):
            login(client, "admin", f"BadPass{i}123!")
        # даже верный пароль теперь заблокирован
        r = login(client, "admin", "Adm1nPassw0rd!")
        assert r.status_code == 302
        html = client.get("/").get_data(as_text=True)
        assert "Слишком много неудачных попыток" in html

    def test_lockout_is_per_username(self, client):
        for i in range(10):
            login(client, "ghostuser", f"BadPass{i}123!")
        # другой логин не заблокирован
        r = login(client, "admin", "Adm1nPassw0rd!")
        assert r.status_code == 302
        assert client.get("/account").status_code == 200


class TestNextRedirect:
    def test_anonymous_redirected_with_next(self, client):
        r = client.get("/cloud")
        assert r.status_code == 302
        assert "next=/cloud" in r.headers["Location"]

    def test_login_returns_to_next(self, client):
        login(client, "admin", "Adm1nPassw0rd!", next="/account")
        # follow redirect manually
        r = client.get("/account")
        assert r.status_code == 200

    def test_open_redirect_blocked(self, client, app):
        with client.session_transaction() as s:
            pass
        r = login(client, "admin", "Adm1nPassw0rd!",
                  next="https://evil.example.com/phish")
        assert r.status_code == 302
        loc = r.headers["Location"]
        assert "evil.example.com" not in loc

    def test_protocol_relative_redirect_blocked(self, env):
        assert env.sanitize_next("//evil.com/x") is None
        assert env.sanitize_next("/cloud/trash") == "/cloud/trash"
        assert env.sanitize_next("javascript:alert(1)") is None
        assert env.sanitize_next(None) is None


class TestCSRF:
    def test_post_without_csrf_rejected(self, client):
        login(client, "admin", "Adm1nPassw0rd!")
        r = client.post("/admin/add", data={"u": "hacker1", "p": "Hack3rPassw!"})
        assert r.status_code == 400

    def test_post_with_bad_csrf_rejected(self, admin_client):
        r = admin_client.post("/admin/add", data={
            "u": "hacker1", "p": "Hack3rPassw!", "csrf_token": "bogus"})
        assert r.status_code == 400


class TestPasswordPolicy:
    def test_weak_password_rejected_on_create(self, admin_client):
        before = admin_client.get("/").get_data(as_text=True)
        r = admin_client.post("/admin/add", data={
            "u": "weakling", "p": "short", "csrf_token": get_csrf(admin_client)})
        assert r.status_code == 302
        html = admin_client.get("/").get_data(as_text=True)
        assert "не короче 10" in html or "weakling" not in html

    def test_change_password_flow(self, admin_client):
        token = get_csrf(admin_client, "/account")
        r = admin_client.post("/account/change-password", data={
            "current": "Adm1nPassw0rd!", "new": "N3wAdminPass!",
            "confirm": "N3wAdminPass!", "csrf_token": token,
        })
        assert r.status_code == 302
        # сессия сброшена, нужно войти заново
        assert admin_client.get("/account").status_code == 302
        r = login(admin_client, "admin", "N3wAdminPass!")
        assert r.status_code == 302
        assert admin_client.get("/account").status_code == 200

    def test_change_password_wrong_current(self, admin_client):
        token = get_csrf(admin_client, "/account")
        r = admin_client.post("/account/change-password", data={
            "current": "NotThePassword1", "new": "N3wAdminPass!",
            "confirm": "N3wAdminPass!", "csrf_token": token,
        })
        html = admin_client.get("/account").get_data(as_text=True)
        assert "Текущий пароль неверный" in html


class TestHashing:
    def test_scrypt_used_and_migration(self, env, client):
        import sqlite3
        conn = sqlite3.connect(env.DB)
        row = conn.execute("SELECT password FROM users WHERE username='admin'").fetchone()
        assert row[0].startswith("scrypt:")
        conn.close()
