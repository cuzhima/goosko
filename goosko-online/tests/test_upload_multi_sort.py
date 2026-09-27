"""Тесты множественной загрузки (upload-multi), дедупликации single/big-загрузки и сортировки."""
import io
import os
import re
import time

from tests.conftest import get_csrf


def _set_setting(env, key, value):
    with env.app.app_context():
        db = env.get_db()
        db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, str(value)),
        )
        db.commit()


def _make_user(env, username, password, is_admin=0):
    with env.app.app_context():
        db = env.get_db()
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?,?,?)",
            (username, env.generate_password_hash(password), is_admin),
        )
        db.commit()


def _multi(client, files, zone="private", token=None):
    csrf_token = token if token is not None else get_csrf(client, "/cloud")
    data = {"csrf_token": csrf_token, "zone": zone}
    for body, name in files:
        data.setdefault("files", []).append((io.BytesIO(body), name))
    return client.post(
        "/cloud/upload-multi", data=data, content_type="multipart/form-data"
    )


# ---------------------------------------------------------------- upload-multi

class TestUploadMulti:
    def test_anonymous_rejected(self, client):
        rv = client.post("/cloud/upload-multi", data={})
        assert rv.status_code == 302  # redirect на /login

    def test_no_files_returns_400_json(self, alice):
        token = get_csrf(alice, "/cloud")
        rv = alice.post("/cloud/upload-multi", data={"csrf_token": token})
        assert rv.status_code == 400
        assert rv.is_json
        body = rv.get_json()
        assert body["ok"] == []
        assert body["errors"]

    def test_missing_csrf_rejected(self, alice):
        rv = alice.post(
            "/cloud/upload-multi",
            data={"files": [(io.BytesIO(b"hello"), "a.txt")]},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 400
        assert "устарела" in rv.get_json()["errors"][0]

    def test_multiple_files_uploaded(self, alice):
        rv = _multi(alice, [
            (b"content one", "one.txt"),
            (b"content two", "two.txt"),
            (b"content three", "three.txt"),
        ])
        assert rv.status_code == 200, rv.get_data(as_text=True)
        body = rv.get_json()
        assert len(body["ok"]) == 3
        assert body["errors"] == []
        names = sorted(i["name"] for i in body["ok"])
        assert names == ["one.txt", "three.txt", "two.txt"]
        # файлы реально доступны для скачивания
        dl = alice.get(body["ok"][0]["url"])
        assert dl.status_code == 200

    def test_path_traversal_neutralized(self, alice, env):
        """../../evil -> secure_filename, за пределы хранилища не выходит."""
        rv = _multi(alice, [(b"bad", "../../evil.txt")])
        body = rv.get_json()
        leaked = [p for p in os.listdir(str(env.STORAGE_DIR)) if "evil" in p]
        assert not leaked
        for item in body["ok"]:
            assert ".." not in item["url"]

    def test_public_zone_restricted_ext_for_user(self, alice):
        rv = _multi(alice, [(b"MZ....", "virus.exe")], zone="public")
        assert rv.status_code == 400
        body = rv.get_json()
        assert body["ok"] == []
        assert any("запрещён" in e for e in body["errors"])

    def test_quota_enforced_via_multi(self, alice, env):
        _set_setting(env, "user_quota_bytes", 50)
        rv = _multi(alice, [(b"x" * 200, "big.txt")])
        body = rv.get_json()
        assert body["ok"] == []
        assert any("вота" in e for e in body["errors"])
        _set_setting(env, "user_quota_bytes", 500 * 1024 * 1024)

    def test_audit_recorded(self, alice, env):
        _multi(alice, [(b"audit me", "audited.txt")])
        with env.app.app_context():
            db = env.get_db()
            row = db.execute(
                "SELECT action FROM audit_log WHERE action='upload_multi' "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
        assert row is not None


# -------------------------------------------------- single upload (после дедупа)

class TestSingleUploadStillWorks:
    def test_private_upload_ok(self, alice):
        token = get_csrf(alice, "/cloud")
        rv = alice.post(
            "/cloud/upload",
            data={
                "csrf_token": token,
                "zone": "private",
                "file": (io.BytesIO(b"single file body"), "single.txt"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert rv.status_code == 200
        html = rv.get_data(as_text=True)
        assert "single.txt" in html
        assert "Файл загружен" in html

    def test_bad_zone_rejected(self, alice, env):
        token = get_csrf(alice, "/cloud")
        rv = alice.post(
            "/cloud/upload",
            data={
                "csrf_token": token,
                "zone": "etc",
                "file": (io.BytesIO(b"x"), "passwd.txt"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert "Неверная зона" in rv.get_data(as_text=True)
        # нигде вне хранилища файл не появился
        found = []
        for root, dirs, files in os.walk(os.path.dirname(str(env.STORAGE_DIR))):
            if "passwd.txt" in files and "storage" not in root:
                found.append(root)
            dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
        assert not found

    def test_empty_filename_shows_error(self, alice):
        token = get_csrf(alice, "/cloud")
        rv = alice.post(
            "/cloud/upload",
            data={"csrf_token": token, "zone": "private",
                  "file": (io.BytesIO(b"x"), "")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert "Файл не выбран" in rv.get_data(as_text=True)

    def test_admin_upload_to_other_user_private(self, admin_client, env):
        _make_user(env, "targetuser", "Str0ngPass!")
        token = get_csrf(admin_client, "/cloud")
        rv = admin_client.post(
            "/cloud/upload",
            data={
                "csrf_token": token,
                "zone": "private",
                "target_user": "targetuser",
                "file": (io.BytesIO(b"from admin"), "gift.txt"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert rv.status_code == 200
        with env.app.app_context():
            db = env.get_db()
            row = db.execute(
                "SELECT owner, zone FROM files WHERE original_name='gift.txt'"
            ).fetchone()
        assert row is not None and row["owner"] == "targetuser"
        assert os.path.exists(os.path.join(str(env.PRIVATE_DIR), "targetuser", "gift.txt"))

    def test_nonadmin_cannot_target_other_user(self, alice, env):
        """target_user игнорируется для не-админа — файл уходит себе."""
        _make_user(env, "victimuser", "Str0ngPass!")
        token = get_csrf(alice, "/cloud")
        rv = alice.post(
            "/cloud/upload",
            data={
                "csrf_token": token,
                "zone": "private",
                "target_user": "victimuser",
                "file": (io.BytesIO(b"spam"), "spam.txt"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert rv.status_code == 200
        with env.app.app_context():
            db = env.get_db()
            row = db.execute(
                "SELECT owner FROM files WHERE original_name='spam.txt'"
            ).fetchone()
        assert row is not None and row["owner"] == "alice"
        assert not os.path.exists(os.path.join(str(env.PRIVATE_DIR), "victimuser", "spam.txt"))


# ---------------------------------------------------------------- upload-big дедуп

class TestUploadBigDedup:
    def _token_for(self, env):
        with env.app.app_context():
            return env.make_upload_token("alice")

    def test_big_upload_private(self, alice, env):
        tok = self._token_for(env)
        rv = alice.post(
            f"/upload-big/{tok}",
            data={"zone": "private", "file": (io.BytesIO(b"big content here"), "big.txt")},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 200
        assert "загружен" in rv.get_data(as_text=True)
        assert os.path.exists(os.path.join(str(env.PRIVATE_DIR), "alice", "big.txt"))

    def test_big_upload_bad_ext_status_400(self, alice, env):
        tok = self._token_for(env)
        rv = alice.post(
            f"/upload-big/{tok}",
            data={"zone": "public", "file": (io.BytesIO(b"MZ"), "malware.exe")},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 400

    def test_big_upload_quota_status_413(self, alice, env):
        _set_setting(env, "user_quota_bytes", 50)
        tok = self._token_for(env)
        rv = alice.post(
            f"/upload-big/{tok}",
            data={"zone": "private", "file": (io.BytesIO(b"x" * 300), "over.txt")},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 413
        _set_setting(env, "user_quota_bytes", 500 * 1024 * 1024)

    def test_invalid_token_403(self, alice):
        rv = alice.post(
            "/upload-big/deadbeef",
            data={"zone": "private", "file": (io.BytesIO(b"x"), "f.txt")},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 403


# ---------------------------------------------------------------- sort

class TestSort:
    FILES = [("zz-old.txt", b"1"), ("aa-new.txt", b"2"), ("mm-mid.txt", b"3")]

    def _upload_several(self, client):
        token = get_csrf(client, "/cloud")
        for name, body in self.FILES:
            rv = _multi(client, [(body, name)], token=token)
            assert rv.status_code == 200, rv.get_data(as_text=True)
            time.sleep(0.02)  # чтобы created_ms различался

    def _rendered_private_order(self, html):
        """Порядок имён файлов именно в таблице приватной зоны."""
        section = html.split("Приватная зона", 1)[1]
        names = [n for n, _ in self.FILES]
        # id ссылок вида /private/alice/<name> идут по строкам таблицы
        ids = re.findall(r"/private/alice/([a-z]+-\w+\.txt)", section)
        out = []
        for i in ids:
            if i in names and (not out or out[-1] != i):
                out.append(i)
        return out

    def test_sort_new_default(self, alice):
        self._upload_several(alice)
        html = alice.get("/cloud?sort=new").get_data(as_text=True)
        assert self._rendered_private_order(html) == [
            "mm-mid.txt", "aa-new.txt", "zz-old.txt"
        ]

    def test_sort_old(self, alice):
        self._upload_several(alice)
        with alice.application.app_context():
            from app import get_db
            rows = get_db().execute(
                "SELECT original_name FROM files"
                " ORDER BY COALESCE(created_ms, strftime('%s', created_at)*1000) ASC,"
                " id DESC"
            ).fetchall()
            expected = [r["original_name"] for r in rows]
        assert len(expected) >= 3
        html = alice.get("/cloud?sort=old").get_data(as_text=True)
        assert self._rendered_private_order(html) == expected[:3]

    def test_sort_name_asc_desc(self, alice):
        self._upload_several(alice)
        asc = alice.get("/cloud?sort=name_asc").get_data(as_text=True)
        desc = alice.get("/cloud?sort=name_desc").get_data(as_text=True)
        names = sorted(n for n, _ in self.FILES)  # aa, mm, zz
        assert asc.find(names[0]) < asc.find(names[1]) < asc.find(names[2])
        assert desc.find(names[2]) < desc.find(names[1]) < desc.find(names[0])

    def test_sort_size(self, alice):
        token = get_csrf(alice, "/cloud")
        for name, size in [("small.bin", 10), ("huge.bin", 1000), ("mid.bin", 100)]:
            rv = _multi(alice, [(b"x" * size, name)], token=token)
            assert rv.status_code == 200
        asc = alice.get("/cloud?sort=size_asc").get_data(as_text=True)
        desc = alice.get("/cloud?sort=size_desc").get_data(as_text=True)
        assert asc.find("small.bin") < asc.find("mid.bin") < asc.find("huge.bin")
        assert desc.find("huge.bin") < desc.find("mid.bin") < desc.find("small.bin")

    def test_invalid_sort_falls_back(self, alice):
        rv = alice.get("/cloud?sort=DROP%20TABLE")
        assert rv.status_code == 200

    def test_sort_selector_in_ui(self, alice):
        html = alice.get("/cloud").get_data(as_text=True)
        # Сортировка — через GET-форму с <select name="sort">
        assert 'name="sort"' in html
        assert "Сначала новые" in html
        assert 'value="size_desc"' in html
