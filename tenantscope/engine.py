"""Lifecycle scenario runner, differential oracle checks, and witness minimization."""

import copy
import hashlib
import tempfile
from pathlib import Path

from .lab import canonical, fields, text
from .model import Oracle
from .target import SQLiteTarget

APP_NAME = "TenantScope"
TAGLINE = (
    "Find cross-account leaks that appear only after ownership and permission changes."
)
PORT = 8762
CAPABILITIES = [
    "Run declarative workflows against a real SQLite fixture application and an independent in-memory policy oracle.",
    "Exercise share, revoke, ownership transfer, account deletion, attachments, and queued export execution.",
    "Inspect durable database state as well as response decisions, including writes made before a denial.",
    "Compare seeded and repaired enforcement and minimize a failing workflow while preserving its failure fingerprint.",
    "This is a controlled local application harness, not an unauthenticated scanner for external services.",
]
OPS = {
    "read": (),
    "attachment": (),
    "share": ("target",),
    "revoke": ("target",),
    "transfer": ("target",),
    "delete_document": (),
    "update": ("content",),
    "delete_account": ("target",),
    "queue_export": ("job",),
    "run_export": ("job",),
}


def validate(request):
    fields(request, ("scenario", "mode"))
    if request["mode"] not in ("seeded", "repaired"):
        raise ValueError("mode must be seeded or repaired")
    scenario = request["scenario"]
    fields(scenario, ("name", "users", "documents", "steps"))
    text(scenario["name"], "scenario name")
    if not isinstance(scenario["users"], list) or not 1 <= len(scenario["users"]) <= 32:
        raise ValueError("Use 1–32 users")
    users = {}
    for user in scenario["users"]:
        fields(user, ("id", "tenant"), ("role",))
        ident = text(user["id"], "user id", 64)
        text(user["tenant"], "tenant", 64)
        if ident in users or user.get("role", "member") not in (
            "member",
            "admin",
            "worker",
        ):
            raise ValueError("Duplicate user or invalid role")
        users[ident] = user
    if (
        not isinstance(scenario["documents"], list)
        or not 1 <= len(scenario["documents"]) <= 64
    ):
        raise ValueError("Use 1–64 documents")
    docs = set()
    for document in scenario["documents"]:
        fields(document, ("id", "owner", "content"))
        ident = text(document["id"], "document id", 64)
        text(document["content"], "document content", 4000)
        if ident in docs or document["owner"] not in users:
            raise ValueError("Duplicate document or unknown owner")
        docs.add(ident)
    if (
        not isinstance(scenario["steps"], list)
        or not 1 <= len(scenario["steps"]) <= 200
    ):
        raise ValueError("Use 1–200 workflow steps")
    for step in scenario["steps"]:
        if not isinstance(step, dict) or step.get("op") not in OPS:
            raise ValueError("Unknown workflow operation")
        op = step["op"]
        required = (
            ("actor", "op")
            + OPS[op]
            + (() if op in ("run_export", "delete_account") else ("document",))
        )
        fields(step, required)
        if step["actor"] not in users:
            raise ValueError("Unknown workflow actor")
        if "document" in step:
            text(step["document"], "document", 64)
        if "target" in step and step["target"] not in users:
            raise ValueError("Unknown target account")
        if "job" in step:
            text(step["job"], "job id", 64)
        if "content" in step:
            text(step["content"], "updated content", 4000)
    return scenario


def execute(request):
    scenario = validate(request)
    oracle = Oracle(scenario)
    events, failures = [], []
    with tempfile.TemporaryDirectory(prefix="tenantscope-") as directory:
        target = SQLiteTarget(Path(directory) / "target.db", scenario, request["mode"])
        try:
            for index, step in enumerate(scenario["steps"]):
                expected = oracle.apply(step)
                observed = target.apply(step)
                state_agrees = canonical(oracle.snapshot()) == canonical(
                    target.snapshot()
                )
                decision_agrees = expected["allowed"] == observed["allowed"]
                content_agrees = expected.get("content") == observed.get("content")
                mismatch = not (state_agrees and decision_agrees and content_agrees)
                reason = (
                    "durable_state_mismatch"
                    if not state_agrees
                    else "authorization_mismatch"
                    if not decision_agrees
                    else "content_mismatch"
                    if not content_agrees
                    else "agrees"
                )
                event = {
                    "step": index + 1,
                    "actor": step["actor"],
                    "operation": step["op"],
                    "document": step.get("document", ""),
                    "job": step.get("job", ""),
                    "expected_allow": expected["allowed"],
                    "actual_allow": observed["allowed"],
                    "state_agrees": state_agrees,
                    "mismatch": mismatch,
                    "reason": reason,
                }
                events.append(event)
                if mismatch:
                    failures.append(
                        {
                            "step": index + 1,
                            "actor": step["actor"],
                            "operation": step["op"],
                            "document": step.get("document", ""),
                            "job": step.get("job", ""),
                            "reason": reason,
                            "expected": expected,
                            "observed": observed,
                        }
                    )
            target_state = target.snapshot()
        finally:
            target.close()
    findings = [
        {
            "severity": "high",
            "title": f"Step {f['step']}: {f['reason'].replace('_', ' ')}",
            "detail": f"{f['actor']} / {f['operation']}: oracle allowed={f['expected']['allowed']}; target allowed={f['observed']['allowed']}. Durable state is checked independently of the response.",
        }
        for f in failures
    ]
    return {
        "summary": {
            "steps": len(events),
            "mismatches": len(failures),
            "users": len(scenario["users"]),
            "documents": len(scenario["documents"]),
            "mode": request["mode"],
        },
        "findings": findings,
        "events": events,
        "details": {
            "failures": failures,
            "target_state": target_state,
            "oracle_state": oracle.snapshot(),
            "scenario_sha256": hashlib.sha256(canonical(scenario)).hexdigest(),
            "policy": "Same tenant; owner/admin may manage; explicit shares permit reads. Transfer clears grants. Exports reauthorize at execution. Disabled users lose access.",
        },
    }


def _base(name, steps):
    return {
        "name": name,
        "users": [
            {"id": "alice", "tenant": "red"},
            {"id": "bob", "tenant": "red"},
            {"id": "carol", "tenant": "blue"},
            {"id": "admin", "tenant": "red", "role": "admin"},
            {"id": "worker", "tenant": "system", "role": "worker"},
        ],
        "documents": [
            {
                "id": "roadmap",
                "owner": "alice",
                "content": "Synthetic red-tenant roadmap",
            },
            {
                "id": "blue-note",
                "owner": "carol",
                "content": "Synthetic blue-tenant note",
            },
        ],
        "steps": steps,
    }


def presets():
    specs = [
        (
            "transfer",
            "Former owner after transfer",
            [
                {"actor": "alice", "op": "read", "document": "roadmap"},
                {
                    "actor": "alice",
                    "op": "transfer",
                    "document": "roadmap",
                    "target": "bob",
                },
                {"actor": "alice", "op": "read", "document": "roadmap"},
            ],
        ),
        (
            "revoke",
            "Revoked share stays in cache",
            [
                {
                    "actor": "alice",
                    "op": "share",
                    "document": "roadmap",
                    "target": "bob",
                },
                {"actor": "bob", "op": "read", "document": "roadmap"},
                {
                    "actor": "alice",
                    "op": "revoke",
                    "document": "roadmap",
                    "target": "bob",
                },
                {"actor": "bob", "op": "read", "document": "roadmap"},
            ],
        ),
        (
            "queued-export",
            "Queued export after revocation",
            [
                {
                    "actor": "alice",
                    "op": "share",
                    "document": "roadmap",
                    "target": "bob",
                },
                {
                    "actor": "bob",
                    "op": "queue_export",
                    "document": "roadmap",
                    "job": "export-1",
                },
                {
                    "actor": "alice",
                    "op": "revoke",
                    "document": "roadmap",
                    "target": "bob",
                },
                {"actor": "worker", "op": "run_export", "job": "export-1"},
            ],
        ),
        (
            "attachment",
            "Attachment crosses tenant boundary",
            [{"actor": "carol", "op": "attachment", "document": "roadmap"}],
        ),
        (
            "account-deletion",
            "Deleted account retains cached access",
            [
                {"actor": "alice", "op": "read", "document": "roadmap"},
                {"actor": "admin", "op": "delete_account", "target": "alice"},
                {"actor": "alice", "op": "read", "document": "roadmap"},
            ],
        ),
        (
            "denied-write",
            "Denied operation still deletes data",
            [{"actor": "carol", "op": "delete_document", "document": "roadmap"}],
        ),
        (
            "deleted-export",
            "Queued export after document deletion",
            [
                {
                    "actor": "alice",
                    "op": "queue_export",
                    "document": "roadmap",
                    "job": "export-1",
                },
                {"actor": "alice", "op": "delete_document", "document": "roadmap"},
                {"actor": "worker", "op": "run_export", "job": "export-1"},
            ],
        ),
    ]
    return [
        {
            "id": ident,
            "title": name,
            "summary": "Compare seeded and repaired enforcement on a concrete ownership lifecycle.",
            "input": {"mode": "seeded", "scenario": _base(name, steps)},
        }
        for ident, name, steps in specs
    ]


def benchmark():
    results = []
    for item in presets():
        for mode in ("seeded", "repaired"):
            request = copy.deepcopy(item["input"])
            request["mode"] = mode
            results.append({"scenario": item["id"], **execute(request)["summary"]})
    return results


def _fingerprint(failure):
    return tuple(
        failure[key] for key in ("actor", "operation", "document", "job", "reason")
    )


def minimize(request):
    initial = execute(request)
    if not initial["details"]["failures"]:
        raise ValueError("No failing witness to minimize")
    fingerprint = _fingerprint(initial["details"]["failures"][0])
    current = copy.deepcopy(request)
    original = len(current["scenario"]["steps"])
    evaluations = 0
    index = 0
    while index < len(current["scenario"]["steps"]) and evaluations < 80:
        if len(current["scenario"]["steps"]) == 1:
            break
        candidate = copy.deepcopy(current)
        del candidate["scenario"]["steps"][index]
        result = execute(candidate)
        evaluations += 1
        if any(_fingerprint(f) == fingerprint for f in result["details"]["failures"]):
            current = candidate
            index = 0
        else:
            index += 1
    return {
        "input": current,
        "result": execute(current),
        "original_steps": original,
        "reduced_steps": len(current["scenario"]["steps"]),
        "evaluations": evaluations,
        "complete": evaluations < 80,
        "method": "Greedy one-step deletion preserving the first failure fingerprint; not a globally minimal proof.",
    }


def add_commands(commands):
    parser = commands.add_parser(
        "minimize", help="Reduce a failing lifecycle to a smaller witness"
    )
    parser.add_argument("input")


def cli_request(args):
    import json
    from .lab import read_json

    result = minimize(read_json(Path(args.input).read_bytes()))
    print(json.dumps(result, indent=2))
    raise SystemExit(0)
