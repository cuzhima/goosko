"""Общая фикстура: изолированное окружение для каждого теста.

Каждый тест получает свежий tmp-каталог для STORAGE_DIR и users.db,
созданных админом (admin/Adm1nPassw0rd!) и обычным пользователем
(alice/A1icePassw0rd!). Rate limiting и фоновые потоки отключены.
"""
import os
import re
import sys

import pytest

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "users.db"))
    monkeypatch.setenv("MEDIA_DIR", str(tmp_path / "media"))
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("ADMIN_PASSWORD", "Adm1nPassw0rd!")
    monkeypatch.setenv("RATELIMIT_ENABLED", "0")
    monkeypatch.setenv("GOOSKO_DISABLE_MAINTENANCE", "1")
    monkeypatch.setenv("USE_X_ACCEL", "0")  # в тестах отдаём файлы напрямую

    # Чистим кэш модулей, чтобы app.py заново применил переменные окружения
    for name in list(sys.modules):
        if name == "app" or name.startswith("app."):
            del sys.modules[name]

    sys.path.insert(0, APP_DIR)
    import app as app_module
    yield app_module
    sys.path.remove(APP_DIR)


@pytest.fixture()
def app(env):
    env.app.config["TESTING"] = True
    return env.app


@pytest.fixture()
def client(app):
    return app.test_client()


def get_csrf(client, path="/"):
    """Достаём csrf_token из формы на странице."""
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert m, f"csrf_token не найден на {path}"
    return m.group(1)


def login(client, username, password, **extra):
    token = get_csrf(client)
    data = {"u": username, "p": password, "csrf_token": token}
    data.update(extra)
    return client.post("/login", data=data, follow_redirects=False)


@pytest.fixture()
def admin_client(app):
    c = app.test_client()
    r = login(c, "admin", "Adm1nPassw0rd!")
    assert r.status_code == 302, "админ не смог войти"
    return c


@pytest.fixture()
def alice(app):
    """Создаём пользователя alice через админку и возвращаем её клиент."""
    ac = app.test_client()
    login(ac, "admin", "Adm1nPassw0rd!")
    r = ac.post("/admin/add", data={
        "u": "alice", "p": "A1icePassw0rd!",
        "csrf_token": get_csrf(ac, "/"),
    })
    assert r.status_code == 302
    c = app.test_client()
    r = login(c, "alice", "A1icePassw0rd!")
    assert r.status_code == 302, "alice не смогла войти"
    return c
