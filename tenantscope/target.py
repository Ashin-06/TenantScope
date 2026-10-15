"""Real SQLite fixture application with seeded and repaired enforcement modes."""

import sqlite3


class SQLiteTarget:
    def __init__(self, path, scenario, mode):
        self.mode = mode
        self.cache = set()
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""PRAGMA foreign_keys=ON;
            CREATE TABLE users(id TEXT PRIMARY KEY, tenant TEXT, role TEXT, active INT);
            CREATE TABLE documents(id TEXT PRIMARY KEY, owner TEXT REFERENCES users(id), tenant TEXT, content TEXT);
            CREATE TABLE shares(document TEXT REFERENCES documents(id) ON DELETE CASCADE, actor TEXT REFERENCES users(id), PRIMARY KEY(document,actor));
            CREATE TABLE jobs(id TEXT PRIMARY KEY, requester TEXT, document TEXT, captured_content TEXT);
        """)
        users = {u["id"]: u for u in scenario["users"]}
        self.db.executemany(
            "INSERT INTO users VALUES(?,?,?,1)",
            [
                (u["id"], u["tenant"], u.get("role", "member"))
                for u in scenario["users"]
            ],
        )
        self.db.executemany(
            "INSERT INTO documents VALUES(?,?,?,?)",
            [
                (d["id"], d["owner"], users[d["owner"]]["tenant"], d["content"])
                for d in scenario["documents"]
            ],
        )
        self.db.commit()

    def _user(self, actor):
        return self.db.execute("SELECT * FROM users WHERE id=?", (actor,)).fetchone()

    def _document(self, ident):
        return self.db.execute(
            "SELECT * FROM documents WHERE id=?", (ident,)
        ).fetchone()

    def _read_allowed(self, actor, ident):
        if self.mode == "seeded" and (actor, ident) in self.cache:
            return True
        user, doc = self._user(actor), self._document(ident)
        if not user or not user["active"] or not doc or user["tenant"] != doc["tenant"]:
            return False
        allowed = (
            user["role"] == "admin"
            or doc["owner"] == actor
            or bool(
                self.db.execute(
                    "SELECT 1 FROM shares WHERE document=? AND actor=?", (ident, actor)
                ).fetchone()
            )
        )
        if allowed:
            self.cache.add((actor, ident))
        return allowed

    def _manage_allowed(self, actor, ident):
        user, doc = self._user(actor), self._document(ident)
        return bool(
            user
            and user["active"]
            and doc
            and user["tenant"] == doc["tenant"]
            and (user["role"] == "admin" or doc["owner"] == actor)
        )

    def apply(self, step):
        actor, op, ident = step["actor"], step["op"], step.get("document")
        user = self._user(actor)
        if not user:
            return {"allowed": False}
        if op in ("read", "attachment"):
            doc = self._document(ident)
            allowed = bool(doc) and (
                self.mode == "seeded"
                and op == "attachment"
                or self._read_allowed(actor, ident)
            )
            return {
                "allowed": bool(allowed),
                "content": doc["content"] if allowed else None,
            }
        if op in ("share", "revoke", "transfer", "delete_document", "update"):
            allowed = self._manage_allowed(actor, ident)
            target = self._user(step.get("target"))
            doc = self._document(ident)
            if op in ("share", "transfer"):
                allowed = allowed and bool(
                    target
                    and target["active"]
                    and doc
                    and target["tenant"] == doc["tenant"]
                )
            # Deliberate side-effect-before-authorization defect, confined to fixtures.
            if self.mode == "seeded" and op == "delete_document" and doc:
                self.db.execute("DELETE FROM documents WHERE id=?", (ident,))
                self.db.commit()
                return {"allowed": allowed}
            if not allowed:
                return {"allowed": False}
            if op == "share":
                self.db.execute(
                    "INSERT OR IGNORE INTO shares VALUES(?,?)", (ident, step["target"])
                )
            elif op == "revoke":
                self.db.execute(
                    "DELETE FROM shares WHERE document=? AND actor=?",
                    (ident, step["target"]),
                )
            elif op == "transfer":
                self.db.execute(
                    "UPDATE documents SET owner=? WHERE id=?", (step["target"], ident)
                )
                self.db.execute("DELETE FROM shares WHERE document=?", (ident,))
            elif op == "update":
                self.db.execute(
                    "UPDATE documents SET content=? WHERE id=?",
                    (step["content"], ident),
                )
            else:
                self.db.execute("DELETE FROM documents WHERE id=?", (ident,))
            self.db.commit()
            return {"allowed": True}
        if op == "delete_account":
            target = self._user(step["target"])
            allowed = bool(
                user["active"]
                and target
                and target["active"]
                and (
                    actor == step["target"]
                    or user["role"] == "admin"
                    and user["tenant"] == target["tenant"]
                )
            )
            if allowed:
                self.db.execute(
                    "UPDATE users SET active=0 WHERE id=?", (step["target"],)
                )
                self.db.commit()
            return {"allowed": allowed}
        if op == "queue_export":
            doc = self._document(ident)
            allowed = bool(
                doc
                and self._read_allowed(actor, ident)
                and not self.db.execute(
                    "SELECT 1 FROM jobs WHERE id=?", (step["job"],)
                ).fetchone()
            )
            if allowed:
                self.db.execute(
                    "INSERT INTO jobs VALUES(?,?,?,?)",
                    (step["job"], actor, ident, doc["content"]),
                )
                self.db.commit()
            return {"allowed": allowed}
        if op == "run_export":
            job = self.db.execute(
                "SELECT * FROM jobs WHERE id=?", (step["job"],)
            ).fetchone()
            allowed = bool(user["active"] and user["role"] == "worker" and job)
            if allowed and self.mode == "repaired":
                allowed = self._read_allowed(job["requester"], job["document"])
            doc = self._document(job["document"]) if job else None
            content = (
                (job["captured_content"] if self.mode == "seeded" else doc["content"])
                if allowed
                else None
            )
            return {"allowed": bool(allowed), "content": content}
        raise ValueError(f"Unknown operation: {op}")

    def snapshot(self):
        return {
            "users": [
                (r[0], r[1], bool(r[2]))
                for r in self.db.execute(
                    "SELECT id,tenant,active FROM users ORDER BY id"
                )
            ],
            "documents": [
                tuple(r)
                for r in self.db.execute(
                    "SELECT id,owner,tenant,content FROM documents ORDER BY id"
                )
            ],
            "shares": [
                tuple(r)
                for r in self.db.execute(
                    "SELECT document,actor FROM shares ORDER BY document,actor"
                )
            ],
        }

    def close(self):
        self.db.close()
