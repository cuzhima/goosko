"""Тесты страницы «Быстрый доступ»: камера, скриншоты, питание сервера."""
import os

from tests.conftest import get_csrf


class TestAccessControl:
    def test_anon_redirected(self, client):
        assert client.get("/quick").status_code == 302

    def test_admin_page_ok(self, admin_client):
        r = admin_client.get("/quick")
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        assert "Фото" in html and "Видео" in html


class TestMediaIdWhitelist:
    def test_resolve_valid_names(self, env):
        ok = [
            "cam_photo_20260101_120000_abcd1234.jpg",
            "cam_video_20260101_120000_abcd1234.mp4",
            "screenshot_20260101_120000_abcd1234.png",
        ]
        for name in ok:
            assert env.MEDIA_ID_RE.fullmatch(name), name

    def test_reject_traversal_and_bad_ext(self, env):
        bad = [
            "../../etc/passwd",
            "cam_photo_20260101_120000_abcd1234.exe",
            "evil.sh",
            "cam_photo_2026-01-01_x_abcd1234.jpg",
            "",
            "CAM_PHOTO_20260101_120000_abcd1234.JPG",
        ]
        for name in bad:
            assert env.resolve_media_file(name) is None

    def test_view_unknown_media_404(self, admin_client):
        assert admin_client.get("/quick/media/nope.jpg").status_code == 404

    def test_view_traversal_404(self, admin_client):
        r = admin_client.get("/quick/media/..%2f..%2fusers.db")
        assert r.status_code in (400, 404)


class TestCapture:
    def test_photo_without_ffmpeg_fails_gracefully(self, admin_client, monkeypatch, env):
        # ffmpeg может отсутствовать в CI — роут обязан вернуть redirect + flash,
        # а не упасть с 500
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post("/quick/capture/photo", data={"csrf_token": token})
        assert r.status_code == 302
        html = admin_client.get("/quick").get_data(as_text=True)
        assert "Фото снято" in html or "Не удалось сделать фото" in html

    def test_video_duration_validation(self, admin_client):
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post("/quick/capture/video",
                              data={"csrf_token": token, "duration": "99999"})
        html = admin_client.get("/quick").get_data(as_text=True)
        assert "Длительность" in html

    def test_video_non_numeric_duration(self, admin_client):
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post("/quick/capture/video",
                              data={"csrf_token": token, "duration": "abc"})
        assert r.status_code == 302
        html = admin_client.get("/quick").get_data(as_text=True)
        assert "Длительность" in html


class TestPower:
    def test_power_requires_phrase(self, admin_client):
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post("/quick/power/shutdown",
                              data={"csrf_token": token, "confirm": "может быть"})
        assert r.status_code == 302
        html = admin_client.get("/quick").get_data(as_text=True)
        assert "Я УВЕРЕН" in html

    def test_power_unknown_action_404(self, admin_client):
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post("/quick/power/format-disk",
                              data={"csrf_token": token, "confirm": "Я УВЕРЕН"})
        assert r.status_code == 404

    def test_power_wrong_confirm_not_executed(self, admin_client, monkeypatch):
        calls = []
        monkeypatch.setattr(
            type(admin_client), "post", admin_client.post)  # no-op
        # перехватываем run_cmd на уровне модуля app
        import sys
        app_mod = sys.modules["app"]
        orig = app_mod.run_cmd
        app_mod.run_cmd = lambda cmd, **kw: (calls.append(cmd), (False, "", "blocked"))[1]
        try:
            token = get_csrf(admin_client, "/quick")
            admin_client.post("/quick/power/reboot",
                              data={"csrf_token": token, "confirm": "не та фраза"})
            assert calls == []  # команда не запускалась
        finally:
            app_mod.run_cmd = orig

    def test_power_correct_confirm_executes_script(self, admin_client, monkeypatch):
        import sys
        app_mod = sys.modules["app"]
        calls = []
        orig = app_mod.run_cmd

        def fake_run_cmd(cmd, **kw):
            calls.append(cmd)
            return False, "", "simulated failure"

        app_mod.run_cmd = fake_run_cmd
        try:
            token = get_csrf(admin_client, "/quick")
            admin_client.post("/quick/power/shutdown",
                              data={"csrf_token": token, "confirm": "Я УВЕРЕН"})
            assert len(calls) == 1
            assert calls[0][0] == "sudo"
            assert "poweroff" in calls[0][-1]
        finally:
            app_mod.run_cmd = orig


class TestMediaDeletePurge:
    def test_delete_nonexistent(self, admin_client):
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post("/quick/delete",
                              data={"csrf_token": token, "id": "nope.jpg"})
        html = admin_client.get("/quick").get_data(as_text=True)
        assert "Файл не найден" in html

    def test_delete_real_file(self, admin_client, env):
        name = "cam_photo_20260101_120000_deadbeef.jpg"
        path = env.MEDIA_DIR / name
        path.write_bytes(b"fake jpg")
        token = get_csrf(admin_client, "/quick")
        admin_client.post("/quick/delete",
                          data={"csrf_token": token, "id": name})
        assert not path.exists()

    def test_purge_removes_all(self, admin_client, env):
        (env.MEDIA_DIR / "cam_photo_20260101_120000_aaaaaaaa.jpg").write_bytes(b"x")
        (env.MEDIA_DIR / "cam_video_20260101_120000_bbbbbbbb.mp4").write_bytes(b"x")
        token = get_csrf(admin_client, "/quick")
        admin_client.post("/quick/purge", data={"csrf_token": token})
        remaining = [p.name for p in env.MEDIA_DIR.iterdir()
                     if env.MEDIA_ID_RE.fullmatch(p.name)]
        assert remaining == []
