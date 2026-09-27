"""Тесты страницы резервного копирования /admin/backup."""
import io
import sqlite3
import tarfile

from tests.conftest import get_csrf, login


def _audit_actions(client, env):
    con = sqlite3.connect(env.DB)
    try:
        return [r[0] for r in con.execute("SELECT action FROM audit_log")]
    finally:
        con.close()


class TestBackupAccess:
    def test_anon_redirected(self, client):
        assert client.get("/admin/backup").status_code in (302, 301)

    def test_non_admin_forbidden(self, alice):
        assert alice.get("/admin/backup").status_code == 403

    def test_admin_ok(self, admin_client):
        r = admin_client.get("/admin/backup")
        assert r.status_code == 200
        assert r.mimetype == "application/gzip"
        assert "attachment" in r.headers.get("Content-Disposition", "")
        assert "goosko-backup_" in r.headers["Content-Disposition"]


class TestBackupContent:
    def test_archive_structure(self, admin_client):
        r = admin_client.get("/admin/backup")
        tf = tarfile.open(fileobj=io.BytesIO(r.data), mode="r:gz")
        names = tf.getnames()
        assert set(names) == {"users.db", "storage_manifest.txt", "README.txt"}

    def test_db_dump_is_valid_and_consistent(self, admin_client, env):
        r = admin_client.get("/admin/backup")
        tf = tarfile.open(fileobj=io.BytesIO(r.data), mode="r:gz")
        member = tf.extractfile("users.db").read()
        # дамп — валидная SQLite-база с таблицами приложения
        con = sqlite3.connect("file::memory:?cache=shared", uri=True)
        try:
            with open("/tmp/_bk_test.db", "wb") as f:
                f.write(member)
            con.close()
            con = sqlite3.connect("/tmp/_bk_test.db")
            tables = {t[0] for t in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            assert {"users", "files", "settings", "audit_log"} <= tables
            n_users = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            assert n_users >= 1  # admin из фикстуры
        finally:
            con.close()

    def test_manifest_lists_storage_files(self, admin_client, env):
        # кладём файл в публичную зону
        import os
        pub = env.PUBLIC_DIR
        with open(os.path.join(pub, "sample.txt"), "w") as f:
            f.write("hello")
        r = admin_client.get("/admin/backup")
        tf = tarfile.open(fileobj=io.BytesIO(r.data), mode="r:gz")
        manifest = tf.extractfile("storage_manifest.txt").read().decode("utf-8")
        lines = [l for l in manifest.splitlines() if "sample.txt" in l]
        assert lines, "файл не попал в манифест"
        path, size, mtime = lines[0].split("\t")
        assert size == "5" and int(mtime) > 0

    def test_readme_mentions_restore(self, admin_client):
        r = admin_client.get("/admin/backup")
        tf = tarfile.open(fileobj=io.BytesIO(r.data), mode="r:gz")
        readme = tf.extractfile("README.txt").read().decode("utf-8")
        assert "Restore" in readme


class TestBackupAudit:
    def test_download_audited(self, admin_client, env):
        admin_client.get("/admin/backup")
        assert "backup_downloaded" in _audit_actions(admin_client, env)

    def test_too_large_db_returns_413(self, admin_client, env, monkeypatch):
        monkeypatch.setattr(env, "BACKUP_MAX_DB_BYTES", 10)  # 10 байт
        assert admin_client.get("/admin/backup").status_code == 413
        # и при этом не записан успех
        assert "backup_downloaded" not in _audit_actions(admin_client, env)


class TestBackupUi:
    def test_admin_page_has_link(self, admin_client):
        html = admin_client.get("/").get_data(as_text=True)  # админ-панель на главной
        assert "Резервная копия" in html and "/admin/backup" in html
