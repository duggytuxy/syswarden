"""Offline pinned partner-job checks, not native HTTP enforcement evidence."""

import ast
from contextlib import suppress
import hashlib
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import runpy
import sys
import types
import typing
import unittest
from unittest.mock import patch


FIXTURE = Path(__file__).parent / "fixtures/bunkerweb-cache-v1.13"
MANIFEST_SHA256 = "40ad2f8699fea9afd8756b931b82882ba953ba01d60cd7a3516bf26cef89e7d9"
ADDRESS = "192.0.2.123"
OLD_LIST = (ADDRESS + "\n").encode()


def selected_functions(filename, names, namespace):
    """Load only named pure helpers from the integrity-checked public fixture."""
    tree = ast.parse((FIXTURE / filename).read_text())
    functions = [node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in functions} != set(names) or len(functions) != len(names):
        raise AssertionError("pinned helper inventory changed")
    exec(compile(ast.Module(body=functions, type_ignores=[]), filename, "exec"), namespace)


class FakeCache:
    """In-memory scheduler dependency. It does not model applied worker state."""

    def __init__(self, contents=None, fresh=False, fail=None):
        self.contents = dict(contents or {})
        self.fresh = fresh
        self.fail = fail
        self.calls = []

    def is_cached_file(self, name, interval):
        return self.fresh and name in self.contents

    def cache_hash(self, name):
        return hashlib.sha256(self.contents[name]).hexdigest() if name in self.contents else None

    def get_cache(self, name):
        return self.contents.get(name)

    def cache_file(self, name, data, **_kwargs):
        if name == self.fail:
            return False, "synthetic cache-write failure"
        self.contents[name] = data
        return True, None

    def del_cache(self, name):
        self.contents.pop(name, None)


class QuietLogger:
    def __getattr__(self, _name):
        return lambda *_args, **_kwargs: None


class BunkerWebCacheRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        wire = (FIXTURE / "provenance.json").read_bytes()
        if hashlib.sha256(wire).hexdigest() != MANIFEST_SHA256:
            raise AssertionError("pinned upstream provenance changed without review")
        manifest = json.loads(wire)
        for name, record in manifest["files"].items():
            data = (FIXTURE / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise AssertionError(f"upstream bytes changed: {name}")
        cls.namespace = {**vars(typing), "suppress": suppress,
                         "ip_address": ip_address, "ip_network": ip_network}
        selected_functions("syswarden_helpers.py.txt", {
            "check_line", "serialize_addresses", "extract_whitelist_ips",
            "delivery_status", "extract_instance_bans",
        }, cls.namespace)
        selected_functions("syswarden_client.py.txt", {"extract_ips"}, cls.namespace)

    def execute_job(self, cache, peers, whitelist=False, settings=None):
        helpers = types.ModuleType("syswarden_helpers")
        for name in ("serialize_addresses", "extract_whitelist_ips", "delivery_status"):
            setattr(helpers, name, self.namespace[name])
        # Own-claim exclusion is not exercised by this bounded harness.
        helpers.load_registry = lambda _value: self.fail("unexpected registry access")
        client = types.ModuleType("syswarden_client")
        client.extract_ips = self.namespace["extract_ips"]
        client.get_timeout = lambda: 5
        client.get_peers = lambda _logger: list(peers)
        client.make_session = lambda _logger: object()

        def call(_session, peer, method, path, **_kwargs):
            cache.calls.append((peer, method, path))
            return peers[peer][path]

        client.call = call
        logger = types.ModuleType("logger")
        logger.setup_logger = lambda *_args: QuietLogger()
        common = types.ModuleType("common_utils")
        common.bytes_hash = lambda data: hashlib.sha256(data).hexdigest()
        jobs = types.ModuleType("jobs")
        jobs.Job = lambda *_args: cache
        modules = {"syswarden_helpers": helpers, "syswarden_client": client,
                   "logger": logger, "common_utils": common, "jobs": jobs}
        environment = {"USE_SYSWARDEN": "yes", "USE_SYSWARDEN_BLOCKLIST": "yes",
                       "USE_SYSWARDEN_WHITELIST": "yes" if whitelist else "no",
                       "SYSWARDEN_BLOCKLIST_EXCLUDE_OWN": "no"}
        environment.update(settings or {})
        original_path = sys.path[:]
        try:
            with patch.dict(sys.modules, modules), patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(SystemExit) as result:
                    runpy.run_path(str(FIXTURE / "syswarden-blocklist-download.py.txt"), run_name="__main__")
                return result.exception.code
        finally:
            sys.path[:] = original_path

    def test_poll_interval_and_scheduler_are_explicit(self):
        plugin = json.loads((FIXTURE / "plugin.json.txt").read_text())
        self.assertEqual(plugin["version"], "1.13")
        setting = plugin["settings"]["SYSWARDEN_BLOCKLIST_INTERVAL"]
        self.assertEqual(setting["default"], "hour")
        self.assertEqual(set(setting["select"]), {"hour", "day"})
        job = next(job for job in plugin["jobs"] if job["name"] == "syswarden-blocklist-download")
        self.assertEqual(job["every"], "hour")

    def test_fresh_cache_does_not_observe_peer_withdrawal(self):
        for interval in ("hour", "day"):
            with self.subTest(interval=interval):
                cache = FakeCache({"blocklist.list": OLD_LIST}, fresh=True)
                self.assertEqual(self.execute_job(cache, {"peer-a": {"/ha/sync": (True, {"ips": None})}},
                                                 settings={"SYSWARDEN_BLOCKLIST_INTERVAL": interval}), 0)
                self.assertEqual(cache.calls, [])
                self.assertEqual(cache.contents["blocklist.list"], OLD_LIST)

    def test_successful_last_entry_withdrawal_requests_reload(self):
        # The real SysWarden API preserves {"ips":null} for an empty list.
        for empty in (None, []):
            with self.subTest(empty=empty):
                cache = FakeCache({"blocklist.list": OLD_LIST})
                self.assertEqual(self.execute_job(cache, {"peer-a": {"/ha/sync": (True, {"ips": empty})}}), 1)
                self.assertEqual(cache.contents["blocklist.list"], b"")
                self.assertEqual(cache.calls, [("peer-a", "GET", "/ha/sync")])
                cache.calls.clear()
                self.assertEqual(self.execute_job(cache, {"peer-a": {"/ha/sync": (True, {"ips": empty})}}), 0)

    def test_remaining_peer_claim_is_not_a_global_unban(self):
        cache = FakeCache({"blocklist.list": OLD_LIST})
        peers = {"peer-a": {"/ha/sync": (True, {"ips": None})},
                 "peer-b": {"/ha/sync": (True, {"ips": [ADDRESS]})}}
        self.assertEqual(self.execute_job(cache, peers), 0)
        self.assertEqual(cache.contents["blocklist.list"], OLD_LIST)
        self.assertEqual(len(cache.calls), 2)

    def test_failed_or_malformed_collection_preserves_previous_lists(self):
        for reply in ((False, "synthetic failure"), (True, {}), (True, {"ips": "invalid"}),
                      (True, {"ips": ["not-an-address"]})):
            with self.subTest(reply=reply):
                original = {"blocklist.list": OLD_LIST, "whitelist.list": b"192.0.2.124\n"}
                cache = FakeCache(original)
                peers = {"peer-a": {"/ha/sync": (True, {"ips": None})}, "peer-b": {"/ha/sync": reply}}
                self.assertEqual(self.execute_job(cache, peers), 2)
                self.assertEqual(cache.contents, original)

    def test_cache_write_failure_does_not_claim_delivery(self):
        cache = FakeCache({"blocklist.list": OLD_LIST}, fail="blocklist.list")
        self.assertEqual(self.execute_job(cache, {"peer-a": {"/ha/sync": (True, {"ips": None})}}), 2)
        self.assertEqual(cache.contents, {"blocklist.list": OLD_LIST})

    def test_partial_write_retries_delivery_even_when_cache_is_fresh(self):
        cache = FakeCache({"blocklist.list": OLD_LIST, "whitelist.list": OLD_LIST}, fail="whitelist.list")
        peers = {"peer-a": {"/ha/sync": (True, {"ips": None}),
                            "/ha/telemetry": (True, {"whitelist": {"ips": []}})}}
        self.assertEqual(self.execute_job(cache, peers, whitelist=True), 2)
        self.assertEqual(cache.contents, {"blocklist.list": b"", "whitelist.list": OLD_LIST, "pending_delivery": b"1"})
        cache.fail, cache.fresh = None, True
        cache.calls.clear()
        self.assertEqual(self.execute_job(cache, peers, whitelist=True), 1)
        self.assertEqual(cache.calls, [])
        self.assertNotIn("pending_delivery", cache.contents)
        # Status 1 requests delivery only. No worker acknowledgement is simulated.
        self.assertEqual(cache.contents["whitelist.list"], OLD_LIST)

    def test_disabled_integration_never_contacts_peers(self):
        cache = FakeCache({"blocklist.list": OLD_LIST})
        self.assertEqual(self.execute_job(cache, {}, settings={"USE_SYSWARDEN": "no"}), 0)
        self.assertEqual(cache.calls, [])
        self.assertEqual(cache.contents["blocklist.list"], OLD_LIST)

    def test_empty_reverse_inventory_requires_complete_success(self):
        extract = self.namespace["extract_instance_bans"]
        self.assertEqual(extract({"instance-a": {"status": "success", "msg": ""}}, 1), [])
        self.assertIsNone(extract({"instance-a": {"status": "error", "msg": ""}}, 1))
        self.assertIsNone(extract({}, 1))
        self.assertIsNone(extract({"instance-a": {"status": "success", "msg": ""}}, 2))


if __name__ == "__main__":
    unittest.main()
