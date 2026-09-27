"""Тесты облака: загрузка, права доступа, path traversal, корзина, шаринг."""
import io

from tests.conftest import get_csrf, login


def upload(client, filename, content=b"hello", zone="private", **extra):
    data = {
        "file": (io.BytesIO(content), filename),
        "zone": zone,
        "csrf_token": get_csrf(client, "/cloud"),
    }
    data.update(extra)
    return client.post("/cloud/upload", data=data,
                       content_type="multipart/form-data")


class TestUpload:
    def test_upload_private(self, alice):
        r = upload(alice, "note.txt", b"secret data")
        assert r.status_code == 302
        page = alice.get("/cloud").get_data(as_text=True)
        assert "note.txt" in page

    def test_upload_public_as_user_gets_prefix(self, alice):
        r = upload(alice, "pic.png", b"\x89PNG fake", zone="public")
        assert r.status_code == 302
        with alice.session_transaction() as s:
            pass
        # файл лежит в public/alice/pic*.png — проверяем через БД
        conn = _db(alice)
        row = conn.execute(
            "SELECT rel_path FROM files WHERE original_name LIKE 'pic%'").fetchone()
        assert row and row[0].startswith("alice/")

    def test_empty_filename_rejected(self, alice):
        r = upload(alice, "", b"x")
        assert r.status_code == 302

    def test_no_file_selected(self, alice):
        r = alice.post("/cloud/upload", data={
            "zone": "private", "csrf_token": get_csrf(alice, "/cloud")})
        assert r.status_code == 302

    def test_bad_zone_rejected(self, alice):
        r = upload(alice, "f.txt", b"x", zone="../etc")
        html_page = alice.get("/cloud").get_data(as_text=True)
        assert "Неверная зона" in html_page or "f.txt" not in html_page


class TestPathTraversal:
    def test_traversal_in_filename_sanitized(self, alice):
        r = upload(alice, "../../etc/passwd", b"pwned")
        # имя должно быть очищено до "passwd"
        conn = _db(alice)
        row = conn.execute("SELECT rel_path FROM files ORDER BY id DESC LIMIT 1").fetchone()
        assert row is None or ".." not in row[0]
        assert row is None or "/" not in row[0].replace("alice/", "", 1)

    def test_private_other_user_forbidden(self, alice):
        # alice не может читать файлы bob
        r = alice.get("/private/bob/secret.txt")
        assert r.status_code == 403

    def test_private_traversal_in_url(self, alice):
        r = alice.get("/private/alice/../../users.db")
        assert r.status_code in (403, 404)

    def test_public_traversal(self, client):
        r = client.get("/public/../../etc/passwd")
        assert r.status_code in (403, 404)

    def test_anonymous_cannot_see_private(self, client):
        r = client.get("/private/admin/x.txt")
        assert r.status_code == 302  # редирект на логин


class TestPermissions:
    def test_user_cannot_delete_other_file(self, app, alice):
        # загружаем файл от имени admin
        ac = app.test_client()
        login(ac, "admin", "Adm1nPassw0rd!")
        upload(ac, "adminfile.txt", b"admin only")
        conn = _db(ac)
        fid = conn.execute(
            "SELECT id FROM files WHERE original_name='adminfile.txt'").fetchone()[0]

        r = alice.post(f"/cloud/delete/{fid}", data={
            "csrf_token": get_csrf(alice, "/cloud")})
        conn2 = _db(alice)
        row = conn2.execute(
            "SELECT deleted_at FROM files WHERE id=?", (fid,)).fetchone()
        assert row[0] is None  # не удалён

    def test_user_can_delete_own(self, alice):
        upload(alice, "mine.txt", b"mine")
        conn = _db(alice)
        fid = conn.execute(
            "SELECT id FROM files WHERE original_name='mine.txt'").fetchone()[0]
        r = alice.post(f"/cloud/delete/{fid}", data={
            "csrf_token": get_csrf(alice, "/cloud")})
        assert r.status_code == 302
        conn2 = _db(alice)
        row = conn2.execute("SELECT deleted_at, trash_path FROM files WHERE id=?", (fid,)).fetchone()
        assert row[0] is not None and row[1]

    def test_nonadmin_cannot_purge_trash(self, alice):
        r = alice.post("/cloud/purge-trash", data={
            "csrf_token": get_csrf(alice, "/cloud/trash")})
        assert r.status_code == 403

    def test_nonadmin_cannot_access_admin_pages(self, alice):
        for path in ("/ssh", "/quick"):
            assert alice.get(path).status_code == 403

    def test_nonadmin_cannot_add_user(self, alice):
        r = alice.post("/admin/add", data={
            "u": "mallory", "p": "M4lloryPass!",
            "csrf_token": get_csrf(alice, "/")})
        assert r.status_code == 403


class TestTrashRestore:
    def test_restore_flow(self, alice):
        upload(alice, "restoreme.txt", b"data")
        conn = _db(alice)
        fid = conn.execute(
            "SELECT id FROM files WHERE original_name='restoreme.txt'").fetchone()[0]
        alice.post(f"/cloud/delete/{fid}", data={
            "csrf_token": get_csrf(alice, "/cloud")})

        trash_page = alice.get("/cloud/trash").get_data(as_text=True)
        assert "restoreme.txt" in trash_page

        r = alice.post(f"/cloud/restore/{fid}", data={
            "csrf_token": get_csrf(alice, "/cloud/trash")})
        assert r.status_code == 302
        conn2 = _db(alice)
        row = conn2.execute("SELECT deleted_at FROM files WHERE id=?", (fid,)).fetchone()
        assert row[0] is None
        # физический файл вернулся
        page = alice.get("/cloud").get_data(as_text=True)
        assert "restoreme.txt" in page

    def test_cannot_restore_other_users_trash(self, app, alice):
        ac = app.test_client()
        login(ac, "admin", "Adm1nPassw0rd!")
        upload(ac, "admin_secret.txt", b"x")
        conn = _db(ac)
        fid = conn.execute(
            "SELECT id FROM files WHERE original_name='admin_secret.txt'").fetchone()[0]
        ac.post(f"/cloud/delete/{fid}", data={
            "csrf_token": get_csrf(ac, "/cloud")})

        alice.post(f"/cloud/restore/{fid}", data={
            "csrf_token": get_csrf(alice, "/cloud/trash")})
        conn2 = _db(alice)
        row = conn2.execute("SELECT deleted_at FROM files WHERE id=?", (fid,)).fetchone()
        assert row[0] is not None  # остался в корзине


class TestShare:
    def test_share_link_works_and_expires(self, app, alice):
        upload(alice, "shared.txt", b"shared content")
        conn = _db(alice)
        fid = conn.execute(
            "SELECT id FROM files WHERE original_name='shared.txt'").fetchone()[0]
        alice.post(f"/cloud/share/{fid}", data={
            "csrf_token": get_csrf(alice, "/cloud")})
        conn2 = _db(alice)
        token = conn2.execute(
            "SELECT share_token FROM files WHERE id=?", (fid,)).fetchone()[0]
        assert token

        # аноним может скачать по токену
        anon = app.test_client()
        r = anon.get(f"/share/{token}")
        assert r.status_code == 200
        assert r.data == b"shared content"

        # протухший токен -> 404
        conn3 = _db(alice)
        conn3.execute("UPDATE files SET share_expires_at = '2000-01-01 00:00:00' WHERE id=?", (fid,))
        conn3.commit()
        assert anon.get(f"/share/{token}").status_code == 404

    def test_fake_share_token_404(self, client):
        assert client.get("/share/notarealtoken123").status_code == 404


class TestSearch:
    def test_like_wildcards_escaped(self, alice):
        upload(alice, "normal.txt", b"x")
        upload(alice, "a%b.txt", b"x")
        # запрос "%" не должен вернуть всё подряд... но % матчит любое —
        # экранирование означает дословный поиск "процента"
        page = alice.get("/cloud?q=%25").get_data(as_text=True)
        assert "normal.txt" not in page

    def test_search_finds_own(self, alice):
        upload(alice, "findme123.txt", b"x")
        page = alice.get("/cloud?q=findme123").get_data(as_text=True)
        assert "findme123.txt" in page


def _db(client):
    """Открываем тестовую БД напрямую для проверок."""
    import sqlite3
    import os
    db_path = os.environ["DB_PATH"]
    conn = sqlite3.connect(db_path)
    return conn
