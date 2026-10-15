import copy
import sqlite3
import tempfile
import unittest
from pathlib import Path

from tenantscope import engine
from tenantscope.target import SQLiteTarget


class LifecycleTests(unittest.TestCase):
    def test_each_seeded_defect_has_a_repaired_control(self):
        for preset in engine.presets():
            with self.subTest(scenario=preset["id"]):
                request = copy.deepcopy(preset["input"])
                self.assertGreater(engine.execute(request)["summary"]["mismatches"], 0)
                request["mode"] = "repaired"
                self.assertEqual(engine.execute(request)["summary"]["mismatches"], 0)

    def test_denied_write_is_caught_by_independent_database_state(self):
        request = next(
            p["input"] for p in engine.presets() if p["id"] == "denied-write"
        )
        result = engine.execute(request)
        event = result["events"][0]
        self.assertFalse(event["expected_allow"])
        self.assertFalse(event["actual_allow"])
        self.assertEqual(event["reason"], "durable_state_mismatch")

    def test_target_is_a_real_sqlite_database(self):
        request = engine.presets()[0]["input"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.db"
            target = SQLiteTarget(path, request["scenario"], "repaired")
            try:
                target.apply(
                    {
                        "actor": "alice",
                        "op": "transfer",
                        "document": "roadmap",
                        "target": "bob",
                    }
                )
                connection = sqlite3.connect(path)
                try:
                    self.assertEqual(
                        connection.execute(
                            "SELECT owner FROM documents WHERE id='roadmap'"
                        ).fetchone()[0],
                        "bob",
                    )
                finally:
                    connection.close()
            finally:
                target.close()

    def test_minimizer_removes_irrelevant_steps_and_preserves_failure(self):
        request = copy.deepcopy(engine.presets()[0]["input"])
        request["scenario"]["steps"].insert(
            0, {"actor": "carol", "op": "read", "document": "blue-note"}
        )
        result = engine.minimize(request)
        self.assertLess(result["reduced_steps"], result["original_steps"])
        self.assertGreater(result["result"]["summary"]["mismatches"], 0)
        self.assertLessEqual(result["evaluations"], 80)

    def test_repaired_witness_cannot_be_minimized_as_failure(self):
        request = copy.deepcopy(engine.presets()[0]["input"])
        request["mode"] = "repaired"
        with self.assertRaises(ValueError):
            engine.minimize(request)

    def test_unknown_actor_and_operation_are_rejected(self):
        for key, value in [("actor", "not-a-user"), ("op", "run-shell")]:
            request = copy.deepcopy(engine.presets()[0]["input"])
            request["scenario"]["steps"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                engine.execute(request)

    def test_repaired_cross_tenant_share_is_denied(self):
        request = copy.deepcopy(engine.presets()[0]["input"])
        request["mode"] = "repaired"
        request["scenario"]["steps"] = [
            {"actor": "alice", "op": "share", "document": "roadmap", "target": "carol"},
            {"actor": "carol", "op": "read", "document": "roadmap"},
        ]
        result = engine.execute(request)
        self.assertEqual(result["summary"]["mismatches"], 0)
        self.assertTrue(all(not e["actual_allow"] for e in result["events"]))

    def test_export_rechecks_current_content_not_a_stale_snapshot(self):
        request = copy.deepcopy(engine.presets()[0]["input"])
        request["mode"] = "repaired"
        request["scenario"]["steps"] = [
            {"actor": "alice", "op": "queue_export", "document": "roadmap", "job": "j"},
            {
                "actor": "alice",
                "op": "update",
                "document": "roadmap",
                "content": "new content",
            },
            {"actor": "worker", "op": "run_export", "job": "j"},
        ]
        self.assertEqual(engine.execute(request)["summary"]["mismatches"], 0)
