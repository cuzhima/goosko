"""Тесты фоновой видеозаписи (polling-статусы) и живого MJPEG-превью камеры."""
import time

from tests.conftest import get_csrf


def _wait_done(admin_client, task_id, timeout=5.0):
    """Крутится пока задача не перейдёт в done/error (поток записи — реальный)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = admin_client.get(f"/quick/task/{task_id}").get_json()
        if data and data["status"] in ("done", "error"):
            return data
        time.sleep(0.1)
    raise AssertionError("task did not finish in time")


class TestVideoTask:
    def test_video_starts_background_task(self, admin_client):
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post(
            "/quick/capture/video",
            data={"csrf_token": token, "duration": "2"},
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["ok"] is True and len(body["task_id"]) == 32
        # Ответ приходит мгновенно — запись ещё идёт
        status = admin_client.get(f"/quick/task/{body['task_id']}").get_json()
        assert status["status"] in ("running", "done")
        assert status["duration"] == 2

    def test_video_task_completes_with_file(self, admin_client, env, monkeypatch, qa):
        def fake_capture(config, duration):
            path = qa.MEDIA_DIR / f"cam_video_20260101_120000_abcd1234.mp4"
            path.write_bytes(b"fake mp4")
            return True, str(path)

        monkeypatch.setattr(qa, "capture_video", fake_capture)
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post(
            "/quick/capture/video",
            data={"csrf_token": token, "duration": "3"},
            headers={"Accept": "application/json"},
        )
        task_id = r.get_json()["task_id"]
        data = _wait_done(admin_client, task_id)
        assert data["status"] == "done"
        assert data["filename"].startswith("cam_video_")
        assert data["view_url"] == f"/quick/media/{data['filename']}"
        # Готовый файл отдаётся
        assert admin_client.get(data["view_url"]).status_code == 200

    def test_video_task_error_reported(self, admin_client, monkeypatch, env, qa):
        monkeypatch.setattr(
            qa, "capture_video", lambda c, d: (False, "ffmpeg: device busy"))
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post(
            "/quick/capture/video",
            data={"csrf_token": token, "duration": "2"},
            headers={"Accept": "application/json"},
        )
        data = _wait_done(admin_client, r.get_json()["task_id"])
        assert data["status"] == "error"
        assert "device busy" in data["error"]

    def test_form_flow_still_redirects(self, admin_client, monkeypatch, env, qa):
        monkeypatch.setattr(
            qa, "capture_video", lambda c, d: (False, "no camera"))
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post("/quick/capture/video",
                              data={"csrf_token": token, "duration": "2"})
        assert r.status_code == 302
        html = admin_client.get("/quick").get_data(as_text=True)
        assert "Запись видео началась" in html

    def test_task_status_requires_admin(self, client, alice, admin_client):
        token = get_csrf(admin_client, "/quick")
        r = admin_client.post(
            "/quick/capture/video",
            data={"csrf_token": token, "duration": "1"},
            headers={"Accept": "application/json"},
        )
        task_id = r.get_json()["task_id"]
        assert client.get(f"/quick/task/{task_id}").status_code == 302   # аноним
        assert alice.get(f"/quick/task/{task_id}").status_code == 403    # не админ

    def test_task_status_bad_id_404(self, admin_client):
        assert admin_client.get("/quick/task/deadbeef").status_code == 404
        assert admin_client.get("/quick/task/" + "z" * 32).status_code == 404

    def test_unknown_task_404(self, admin_client):
        assert admin_client.get("/quick/task/" + "a" * 32).status_code == 404

    def test_cleanup_tasks_removes_stale(self, app, env, qa):
        with app.app_context():
            db = env.get_db()
            old_running = time.time() - qa.VIDEO_TASK_TTL - 10
            old_done = time.time() - qa.TASK_DONE_TTL - 10
            fresh = time.time()
            for tid, st, ts in [("1" * 32, "running", old_running),
                                ("2" * 32, "done", old_done),
                                ("3" * 32, "running", fresh)]:
                db.execute(
                    "INSERT INTO tasks (id,status,duration,started_at)"
                    " VALUES (?,?,?,?)", (tid, st, 5, ts))
            db.commit()
            qa.cleanup_tasks()
            rows = {r["id"]: r["status"] for r in
                    db.execute("SELECT id,status FROM tasks")}
            assert rows == {"3" * 32: "running"}


class TestCameraStream:
    def test_stream_anon_redirected(self, client):
        assert client.get("/quick/stream.mjpg").status_code == 302

    def test_stream_alice_forbidden(self, alice):
        assert alice.get("/quick/stream.mjpg").status_code == 403

    def test_stream_launches_ffmpeg_and_headers(self, admin_client, monkeypatch, env, qa):
        started = {}

        class FakeProc:
            poll_called = 0

            def poll(self):
                return 0  # процесс «завершён» — генератор сразу остановится

            def terminate(self):
                started["terminated"] = True

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        def fake_popen(cmd, **kwargs):
            started["cmd"] = cmd
            return FakeProc()

        monkeypatch.setattr(qa.subprocess, "Popen", fake_popen)
        r = admin_client.get("/quick/stream.mjpg")
        assert r.status_code == 200
        assert r.headers["Content-Type"].startswith("multipart/x-mixed-replace")
        assert r.headers["Cache-Control"] == "no-store"
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["Content-Security-Policy"] == "default-src 'none'"
        cmd = started["cmd"]
        assert cmd[0] == "ffmpeg" and "-f" in cmd and "v4l2" in cmd
        assert "-" in cmd[-1:] or cmd[-1] == "-"
        # тело прочитано до конца -> ffmpeg-процесс обязан быть убит
        r.get_data()
        assert started.get("terminated") is True

    def test_stream_oserror_502(self, admin_client, monkeypatch, env, qa):
        def boom(*a, **k):
            raise OSError("no such device")

        monkeypatch.setattr(qa.subprocess, "Popen", boom)
        assert admin_client.get("/quick/stream.mjpg").status_code == 502

    def test_preview_toggle_setting(self, admin_client, app, env):
        with app.app_context():
            assert env.effective_camera_preview_enabled() is True
        assert b"stream.mjpg" in admin_client.get("/quick").data
        token = get_csrf(admin_client, "/admin/settings")
        r = admin_client.post("/admin/settings", data={
            "csrf_token": token,
            "user_quota_bytes": str(5 * 1024**3),
            "max_file_size_bytes": str(2 * 1024**3),
            "share_ttl_hours": "72",
            "trash_retention_days": "30",
            "camera_max_video_seconds": "120",
            "camera_preview_enabled": "0",
            "stream_uploads": "1",
        })
        assert r.status_code == 302
        with app.app_context():
            assert env.effective_camera_preview_enabled() is False
        assert b"stream.mjpg" not in admin_client.get("/quick").data


class TestGalleryThumbs:
    def test_gallery_shows_thumbs_for_images_only(self, admin_client, env, qa):
        qa.ensure_dir(str(qa.MEDIA_DIR))
        (qa.MEDIA_DIR / "cam_photo_20260101_120000_aaaaaaaa.jpg").write_bytes(b"x")
        (qa.MEDIA_DIR / "cam_video_20260101_120000_bbbbbbbb.mp4").write_bytes(b"y")
        html = admin_client.get("/quick").get_data(as_text=True)
        assert 'src="/quick/media/cam_photo_20260101_120000_aaaaaaaa.jpg"' in html
        # для видео превью-картинки нет — только ссылка «Открыть»
        assert 'src="/quick/media/cam_video_20260101_120000_bbbbbbbb.mp4"' not in html
