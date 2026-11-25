"""SQLite-backed directory: users, groups, apps, mail and knowledge base documents."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from lab.jsonl import utcnow

SEED_FILE = Path(__file__).parent / "seed" / "tenant.yaml"
_NAMESPACE = uuid.UUID("6f1c9a52-9f0e-4a7e-8f44-000000001ab0")

SCHEMA = """
CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT UNIQUE, upn TEXT UNIQUE, display TEXT, title TEXT,
                    mobile TEXT, password TEXT, password_changes INTEGER DEFAULT 0);
CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT UNIQUE, description TEXT, privileged INTEGER,
                     role_assignable INTEGER, roles TEXT);
CREATE TABLE members (group_id TEXT, user_id TEXT, PRIMARY KEY (group_id, user_id));
CREATE TABLE apps (app_id TEXT PRIMARY KEY, name TEXT UNIQUE, audience TEXT, secret TEXT, public INTEGER,
                   app_roles TEXT, scopes TEXT, roles TEXT, mailbox_scope TEXT);
CREATE TABLE messages (id TEXT PRIMARY KEY, seq INTEGER, mailbox TEXT, sender TEXT, subject TEXT, body TEXT,
                       received TEXT, assertion TEXT);
CREATE TABLE documents (id TEXT PRIMARY KEY, title TEXT, label TEXT, allowed TEXT, content TEXT, author TEXT);
"""


def stable_id(kind: str, name: str) -> str:
    """Deterministic GUIDs, so IDs are identical in every run and can be cited in docs and rules."""
    return str(uuid.uuid5(_NAMESPACE, f"{kind}:{name}"))


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(8)
    digest = hashlib.scrypt(password.encode(), salt=salt.encode(), n=1024, r=8, p=1).hex()
    return f"{salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    return hmac.compare_digest(hash_password(password, stored.split("$", 1)[0]), stored)


@dataclass(frozen=True)
class User:
    id: str
    name: str
    upn: str
    display: str
    title: str
    mobile: str
    password: str
    password_changes: int
    groups: tuple[str, ...] = ()
    roles: frozenset[str] = frozenset()

    @property
    def privileged(self) -> bool:
        return "Global Administrator" in self.roles


@dataclass(frozen=True)
class Group:
    id: str
    name: str
    description: str
    privileged: bool
    role_assignable: bool
    roles: frozenset[str]


@dataclass(frozen=True)
class App:
    app_id: str
    name: str
    audience: str | None
    secret: str | None
    public: bool
    app_roles: frozenset[str] = field(default_factory=frozenset)
    scopes: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    mailbox_scope: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Document:
    id: str
    title: str
    label: str
    allowed_groups: frozenset[str]
    content: str
    author: str

    @property
    def sensitive(self) -> bool:
        return self.label != "General"


class Directory:
    def __init__(self, db_path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self.domain = ""
        self.seed()

    # --- storage helpers -------------------------------------------------------------------------

    def _rows(self, sql: str, *params: Any) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, params).fetchall()

    def _write(self, sql: str, *params: Any) -> None:
        with self._lock:
            self._db.execute(sql, params)
            self._db.commit()

    def seed(self) -> None:
        data = yaml.safe_load(SEED_FILE.read_text(encoding="utf-8"))
        with self._lock:
            for (table,) in self._db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                self._db.execute(f"DROP TABLE {table}")
            self._db.executescript(SCHEMA)
            self.domain = data["domain"]
            for group in data["groups"]:
                self._db.execute(
                    "INSERT INTO groups VALUES (?,?,?,?,?,?)",
                    (
                        stable_id("group", group["name"]),
                        group["name"],
                        group["description"],
                        int(group.get("privileged", False)),
                        int(group.get("is_assignable_to_role", False)),
                        json.dumps(group.get("directory_roles", [])),
                    ),
                )
            for user in data["users"]:
                user_id = stable_id("user", user["name"])
                password = data["default_password_pattern"].format(name=user["name"])
                self._db.execute(
                    "INSERT INTO users (id,name,upn,display,title,mobile,password) VALUES (?,?,?,?,?,?,?)",
                    (
                        user_id,
                        user["name"],
                        f"{user['name']}@{self.domain}",
                        user["display"],
                        user["title"],
                        "",
                        hash_password(password),
                    ),
                )
                for name in user["groups"]:
                    self._db.execute("INSERT INTO members VALUES (?,?)", (stable_id("group", name), user_id))
            for app in data["applications"]:
                self._db.execute(
                    "INSERT INTO apps VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        stable_id("app", app["name"]),
                        app["name"],
                        app.get("audience"),
                        app.get("secret"),
                        int(app.get("public", False)),
                        json.dumps(app.get("app_roles", [])),
                        json.dumps(app.get("delegated_scopes", [])),
                        json.dumps(app.get("directory_roles", [])),
                        json.dumps(app.get("mailbox_scope", [])),
                    ),
                )
            self._db.commit()
        for message in data["messages"]:
            self.deliver(
                f"{message['to']}@{self.domain}",
                f"{message['from']}@{self.domain}",
                message["subject"],
                message["body"],
            )
        for doc in data["documents"]:
            self.add_document(doc["title"], doc["content"], doc["label"], doc["allowed_groups"], "seed")

    # --- users and groups ------------------------------------------------------------------------

    def _user(self, row: sqlite3.Row) -> User:
        groups = self._rows(
            "SELECT g.name, g.roles FROM groups g JOIN members m ON m.group_id=g.id WHERE m.user_id=?", row["id"]
        )
        roles = {role for group in groups for role in json.loads(group["roles"])}
        return User(**dict(row), groups=tuple(sorted(g["name"] for g in groups)), roles=frozenset(roles))

    def users(self) -> list[User]:
        return [self._user(row) for row in self._rows("SELECT * FROM users ORDER BY name")]

    def user(self, key: str) -> User | None:
        rows = self._rows("SELECT * FROM users WHERE id=? OR lower(upn)=lower(?)", key, key)
        return self._user(rows[0]) if rows else None

    def set_password(self, user_id: str, password: str) -> None:
        self._write(
            "UPDATE users SET password=?, password_changes=password_changes+1 WHERE id=?",
            hash_password(password),
            user_id,
        )

    def set_profile(self, user_id: str, title: str | None, mobile: str | None, display: str | None) -> None:
        self._write(
            "UPDATE users SET title=coalesce(?,title), mobile=coalesce(?,mobile),"
            " display=coalesce(?,display) WHERE id=?",
            title,
            mobile,
            display,
            user_id,
        )

    def _group(self, row: sqlite3.Row) -> Group:
        return Group(
            row["id"],
            row["name"],
            row["description"],
            bool(row["privileged"]),
            bool(row["role_assignable"]),
            frozenset(json.loads(row["roles"])),
        )

    def groups(self) -> list[Group]:
        return [self._group(row) for row in self._rows("SELECT * FROM groups ORDER BY name")]

    def group(self, group_id: str) -> Group | None:
        rows = self._rows("SELECT * FROM groups WHERE id=?", group_id)
        return self._group(rows[0]) if rows else None

    def members(self, group_id: str) -> list[User]:
        rows = self._rows(
            "SELECT u.* FROM users u JOIN members m ON m.user_id=u.id WHERE m.group_id=? ORDER BY u.name", group_id
        )
        return [self._user(row) for row in rows]

    def add_member(self, group_id: str, user_id: str) -> bool:
        if any(user.id == user_id for user in self.members(group_id)):
            return False
        self._write("INSERT INTO members VALUES (?,?)", group_id, user_id)
        return True

    # --- applications ----------------------------------------------------------------------------

    def _app(self, row: sqlite3.Row) -> App:
        return App(
            row["app_id"],
            row["name"],
            row["audience"],
            row["secret"],
            bool(row["public"]),
            frozenset(json.loads(row["app_roles"])),
            frozenset(json.loads(row["scopes"])),
            frozenset(json.loads(row["roles"])),
            frozenset(json.loads(row["mailbox_scope"])),
        )

    def apps(self) -> list[App]:
        return [self._app(row) for row in self._rows("SELECT * FROM apps ORDER BY name")]

    def app(self, key: str) -> App | None:
        rows = self._rows("SELECT * FROM apps WHERE app_id=? OR name=?", key, key)
        return self._app(rows[0]) if rows else None

    def set_consent(self, app_id: str, app_roles: list[str], scopes: list[str]) -> None:
        self._write(
            "UPDATE apps SET app_roles=?, scopes=? WHERE app_id=?",
            json.dumps(sorted(app_roles)),
            json.dumps(sorted(scopes)),
            app_id,
        )

    # --- mail and documents ----------------------------------------------------------------------

    def deliver(self, mailbox: str, sender: str, subject: str, body: str, assertion: str | None = None) -> None:
        with self._lock:
            seq = self._db.execute("SELECT count(*) FROM messages").fetchone()[0] + 1
            self._write(
                "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)",
                f"msg-{seq:04d}",
                seq,
                mailbox.lower(),
                sender,
                subject,
                body,
                utcnow(),
                assertion,
            )

    def mailbox(self, upn: str) -> list[sqlite3.Row]:
        return self._rows("SELECT * FROM messages WHERE mailbox=? ORDER BY seq", upn.lower())

    def add_document(self, title: str, content: str, label: str, allowed: list[str], author: str) -> Document:
        doc_id = f"doc-{len(self._rows('SELECT 1 FROM documents')) + 1:03d}"
        self._write(
            "INSERT INTO documents VALUES (?,?,?,?,?,?)", doc_id, title, label, json.dumps(allowed), content, author
        )
        return Document(doc_id, title, label, frozenset(allowed), content, author)

    def documents(self) -> list[Document]:
        return [
            Document(r["id"], r["title"], r["label"], frozenset(json.loads(r["allowed"])), r["content"], r["author"])
            for r in self._rows("SELECT * FROM documents ORDER BY id")
        ]
