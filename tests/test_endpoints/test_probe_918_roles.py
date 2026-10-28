"""THROWAWAY probe for #918 (not for upstream): what may a caller do to a user of
equal or higher role? Records actual HTTP statuses and compares them with the
prediction from reading master; a mismatch fails and pytest prints the diff."""

import os
import unittest
from unittest.mock import patch

from gramps.cli.clidbman import CLIDbManager
from gramps.gen.dbstate import DbState

from gramps_webapi.app import create_app
from gramps_webapi.auth import add_user, get_all_user_details, user_db
from gramps_webapi.auth.const import (
    ROLE_ADMIN,
    ROLE_EDITOR,
    ROLE_MEMBER,
    ROLE_OWNER,
)
from gramps_webapi.const import ENV_CONFIG_FILE, TEST_AUTH_CONFIG

from . import BASE_URL

USERS = {
    # actors
    "owner": (ROLE_OWNER, "tree"),
    "admin": (ROLE_ADMIN, "tree"),
    "editor": (ROLE_EDITOR, "tree"),
    # targets, one per mutating probe so the order does not matter
    "owner_e": (ROLE_OWNER, "tree"),
    "owner_r": (ROLE_OWNER, "tree"),
    "owner_d": (ROLE_OWNER, "tree"),
    "owner_p": (ROLE_OWNER, "tree"),
    "admin_e": (ROLE_ADMIN, "tree"),
    "admin_r": (ROLE_ADMIN, "tree"),
    "admin_d": (ROLE_ADMIN, "tree"),
    "admin_p": (ROLE_ADMIN, "tree"),
    "admin2_e": (ROLE_ADMIN, "tree"),
    "admin2_d": (ROLE_ADMIN, "tree"),
    "member_e": (ROLE_MEMBER, "tree"),
    "nt_admin_e": (ROLE_ADMIN, None),
    "nt_admin_d": (ROLE_ADMIN, None),
}


class TestProbe918Roles(unittest.TestCase):
    def setUp(self):
        self.name = "Test Web API probe 918"
        self.dbman = CLIDbManager(DbState())
        dbpath, _name = self.dbman.create_new_db_cli(self.name, dbid="sqlite")
        self.tree = os.path.basename(dbpath)
        with patch.dict("os.environ", {ENV_CONFIG_FILE: TEST_AUTH_CONFIG}):
            self.app = create_app(
                config={"TESTING": True, "RATELIMIT_ENABLED": False},
                config_from_env=False,
            )
        self.client = self.app.test_client()
        with self.app.app_context():
            user_db.create_all()
            for name, (role, tree) in USERS.items():
                add_user(
                    name=name,
                    password="123",
                    email=f"{name}@example.com",
                    role=role,
                    tree=self.tree if tree else None,
                )
        self.ctx = self.app.test_request_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()
        self.dbman.remove_database(self.name)

    def _hdr(self, name):
        rv = self.client.post(
            BASE_URL + "/token/", json={"username": name, "password": "123"}
        )
        assert rv.status_code == 200, (name, rv.status_code)
        return {"Authorization": f"Bearer {rv.json['access_token']}"}

    def test_probe(self):
        owner, admin, editor = self._hdr("owner"), self._hdr("admin"), self._hdr("editor")

        def put(h, target, body):
            return self.client.put(
                BASE_URL + f"/users/{target}/", headers=h, json=body
            ).status_code

        def delete(h, target):
            return self.client.delete(
                BASE_URL + f"/users/{target}/", headers=h
            ).status_code

        def pw(h, target):
            return self.client.post(
                BASE_URL + f"/users/{target}/password/change",
                headers=h,
                json={"old_password": "123", "new_password": "456"},
            ).status_code

        actual = {
            # controls: lower target allowed, no permission denied, other tree denied
            "owner -> member: edit email": put(owner, "member_e", {"email": "x@example.com"}),
            "editor -> member: edit email": put(editor, "member_e", {"email": "y@example.com"}),
            "owner -> treeless admin: edit email": put(owner, "nt_admin_e", {"email": "x@example.com"}),
            "owner -> treeless admin: delete": delete(owner, "nt_admin_d"),
            # owner -> another owner of the same tree
            "owner -> owner: edit email": put(owner, "owner_e", {"email": "x@example.com"}),
            "owner -> owner: demote to editor": put(owner, "owner_r", {"role": ROLE_EDITOR}),
            "owner -> owner: delete": delete(owner, "owner_d"),
            "owner -> owner: password/change (old pw known)": pw(owner, "owner_p"),
            # owner -> admin who belongs to the same tree
            "owner -> tree admin: edit email": put(owner, "admin_e", {"email": "x@example.com"}),
            "owner -> tree admin: demote to owner": put(owner, "admin_r", {"role": ROLE_OWNER}),
            "owner -> tree admin: delete": delete(owner, "admin_d"),
            "owner -> tree admin: password/change (old pw known)": pw(owner, "admin_p"),
            # admin -> another admin
            "admin -> admin: edit email": put(admin, "admin2_e", {"email": "x@example.com"}),
            "admin -> admin: delete": delete(admin, "admin2_d"),
        }

        with self.app.app_context():
            details = {u["name"]: u for u in get_all_user_details(tree=None, all_trees=True)}
        state = {
            "owner_r role after": details.get("owner_r", {}).get("role"),
            "admin_r role after": details.get("admin_r", {}).get("role"),
            "owner_d exists after": "owner_d" in details,
            "admin_d exists after": "admin_d" in details,
        }

        ok, denied = 200, 403
        predicted = {
            "owner -> member: edit email": ok,
            "editor -> member: edit email": denied,
            "owner -> treeless admin: edit email": denied,
            "owner -> treeless admin: delete": denied,
            "owner -> owner: edit email": ok,
            "owner -> owner: demote to editor": ok,
            "owner -> owner: delete": ok,
            "owner -> owner: password/change (old pw known)": 201,
            "owner -> tree admin: edit email": ok,
            "owner -> tree admin: demote to owner": ok,
            "owner -> tree admin: delete": ok,
            "owner -> tree admin: password/change (old pw known)": 201,
            "admin -> admin: edit email": ok,
            "admin -> admin: delete": ok,
        }
        predicted_state = {
            "owner_r role after": ROLE_EDITOR,
            "admin_r role after": ROLE_OWNER,
            "owner_d exists after": False,
            "admin_d exists after": False,
        }
        print("\nPROBE RESULTS")
        for k, v in {**actual, **state}.items():
            print(f"  {k}: {v}")
        self.assertEqual({**actual, **state}, {**predicted, **predicted_state})
