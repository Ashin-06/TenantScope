"""Independent authorization specification. No target database or target helpers are used."""

import copy


class Oracle:
    def __init__(self, scenario):
        self.users = {u["id"]: {**u, "active": True} for u in scenario["users"]}
        self.docs = {
            d["id"]: {**d, "tenant": self.users[d["owner"]]["tenant"]}
            for d in scenario["documents"]
        }
        self.shares = set()
        self.jobs = {}

    def can_read(self, actor, document):
        user, doc = self.users.get(actor), self.docs.get(document)
        return bool(
            user
            and user["active"]
            and doc
            and user["tenant"] == doc["tenant"]
            and (
                doc["owner"] == actor
                or user.get("role") == "admin"
                or (document, actor) in self.shares
            )
        )

    def can_manage(self, actor, document):
        return self.can_read(actor, document) and (
            self.docs[document]["owner"] == actor
            or self.users[actor].get("role") == "admin"
        )

    def apply(self, step):
        actor, op, doc_id = step["actor"], step["op"], step.get("document")
        user = self.users.get(actor)
        if not user or not user["active"]:
            return {"allowed": False}
        if op in ("read", "attachment"):
            allowed = self.can_read(actor, doc_id)
            return {
                "allowed": allowed,
                "content": self.docs[doc_id]["content"] if allowed else None,
            }
        if op in ("share", "revoke", "transfer", "delete_document", "update"):
            allowed = self.can_manage(actor, doc_id)
            target = self.users.get(step.get("target"))
            if op in ("share", "transfer"):
                allowed = allowed and bool(
                    target
                    and target["active"]
                    and target["tenant"] == self.docs.get(doc_id, {}).get("tenant")
                )
            if not allowed:
                return {"allowed": False}
            if op == "share":
                self.shares.add((doc_id, step["target"]))
            elif op == "revoke":
                self.shares.discard((doc_id, step["target"]))
            elif op == "transfer":
                self.docs[doc_id]["owner"] = step["target"]
                self.shares = {s for s in self.shares if s[0] != doc_id}
            elif op == "delete_document":
                del self.docs[doc_id]
                self.shares = {s for s in self.shares if s[0] != doc_id}
            else:
                self.docs[doc_id]["content"] = step["content"]
            return {"allowed": True}
        if op == "delete_account":
            target_id = step["target"]
            target = self.users.get(target_id)
            allowed = bool(
                target
                and target["active"]
                and (
                    actor == target_id
                    or (
                        user.get("role") == "admin"
                        and user["tenant"] == target["tenant"]
                    )
                )
            )
            if allowed:
                target["active"] = False
            return {"allowed": allowed}
        if op == "queue_export":
            allowed = self.can_read(actor, doc_id) and step["job"] not in self.jobs
            if allowed:
                self.jobs[step["job"]] = {"requester": actor, "document": doc_id}
            return {"allowed": allowed}
        if op == "run_export":
            job = self.jobs.get(step["job"])
            allowed = bool(
                user.get("role") == "worker"
                and job
                and self.can_read(job["requester"], job["document"])
            )
            return {
                "allowed": allowed,
                "content": self.docs[job["document"]]["content"] if allowed else None,
            }
        raise ValueError(f"Unknown operation: {op}")

    def snapshot(self):
        return {
            "users": sorted(
                (u["id"], u["tenant"], u["active"]) for u in self.users.values()
            ),
            "documents": sorted(
                (d["id"], d["owner"], d["tenant"], d["content"])
                for d in self.docs.values()
            ),
            "shares": sorted(self.shares),
        }

    def copy(self):
        return copy.deepcopy(self)
