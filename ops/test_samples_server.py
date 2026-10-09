"""Tests for ops/samples_server.py. Standard library only:

    python3 -m unittest discover -s ops -v
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

import samples_server

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class SamplesServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "samples"
        self.server = samples_server.make_server("127.0.0.1", 0, self.root, TOKEN, max_bytes=1024)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            raw = resp.read()
            data = json.loads(raw) if raw else None
            return resp.status, data, resp
        finally:
            conn.close()

    # --- auth ---------------------------------------------------------------

    def test_healthz_needs_no_token(self) -> None:
        status, data, _ = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(data, {"status": "ok"})

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "root can write anywhere; POSIX only")
    def test_healthz_fails_when_the_drop_is_not_writable(self) -> None:
        self.root.chmod(0o555)
        try:
            status, data, _ = self.request("GET", "/healthz")
        finally:
            self.root.chmod(0o755)
        self.assertEqual(status, 503)
        self.assertIn("not writable", data["error"])

    def test_everything_else_needs_the_token(self) -> None:
        for method, path, body in [
            ("GET", "/samples/", None),
            ("PUT", "/samples/p/a.bin", b"x"),
            ("DELETE", "/samples/p/a.bin", None),
        ]:
            with self.subTest(method=method):
                status, _, resp = self.request(method, path, body)
                self.assertEqual(status, 401)
                self.assertEqual(resp.getheader("WWW-Authenticate"), "Bearer")
                status, _, _ = self.request(method, path, body, {"Authorization": "Bearer wrong"})
                self.assertEqual(status, 401)
        self.assertFalse((self.root / "p" / "a.bin").exists())

    def test_empty_token_is_refused_at_startup(self) -> None:
        with self.assertRaises(ValueError):
            samples_server.make_server("127.0.0.1", 0, self.root, "", max_bytes=1)

    # --- upload -------------------------------------------------------------

    def test_put_creates_then_is_idempotent_then_refuses_overwrite(self) -> None:
        body = b"\x7fELF fake binary"
        status, data, _ = self.request("PUT", "/samples/proj/fw.bin", body, AUTH)
        self.assertEqual(status, 201)
        self.assertEqual(data["path"], str(self.root / "proj" / "fw.bin"))
        self.assertEqual(data["sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(data["size"], len(body))
        self.assertFalse(data["existing"])
        self.assertEqual((self.root / "proj" / "fw.bin").read_bytes(), body)

        status, data, _ = self.request("PUT", "/samples/proj/fw.bin", body, AUTH)
        self.assertEqual(status, 200)
        self.assertTrue(data["existing"])

        status, data, _ = self.request("PUT", "/samples/proj/fw.bin", b"other bytes", AUTH)
        self.assertEqual(status, 409)
        self.assertEqual((self.root / "proj" / "fw.bin").read_bytes(), body)

    def test_no_temp_files_survive(self) -> None:
        self.request("PUT", "/samples/proj/a.bin", b"abc", AUTH)
        self.request("PUT", "/samples/proj/a.bin", b"different", AUTH)  # 409 path
        self.assertEqual(sorted(p.name for p in (self.root / "proj").iterdir()), ["a.bin"])

    def test_stale_temp_files_are_cleared_at_startup(self) -> None:
        (self.root / "proj").mkdir(parents=True)
        stale = self.root / "proj" / ".upload-abc123"
        stale.write_bytes(b"half an upload")
        samples_server.remove_stale_uploads(self.root)
        self.assertFalse(stale.exists())

    def test_oversize_upload_is_refused(self) -> None:
        status, data, _ = self.request("PUT", "/samples/proj/big.bin", b"x" * 1025, AUTH)
        self.assertEqual(status, 413)
        self.assertFalse((self.root / "proj" / "big.bin").exists())

    def test_put_needs_project_and_name(self) -> None:
        status, _, _ = self.request("PUT", "/samples/proj", b"x", AUTH)
        self.assertEqual(status, 405)

    def test_hostile_names_are_refused(self) -> None:
        for path in [
            "/samples/../etc/passwd",
            "/samples/proj/..",
            "/samples/proj/.hidden",
            "/samples/proj/%2e%2e",
            "/samples/proj/a%2Fb",
            "/samples/proj/sp%20ace",
            "/samples/-proj/a.bin",
            "/samplesX/proj/a.bin",
        ]:
            with self.subTest(path=path):
                status, _, _ = self.request("PUT", path, b"x", AUTH)
                self.assertEqual(status, 404)
        self.assertEqual(list(self.root.rglob("*")), [])

    # --- listing + delete ---------------------------------------------------

    def test_listing(self) -> None:
        self.request("PUT", "/samples/alpha/one.bin", b"1", AUTH)
        self.request("PUT", "/samples/alpha/two.bin", b"22", AUTH)
        self.request("PUT", "/samples/beta/x.so", b"333", AUTH)

        status, data, _ = self.request("GET", "/samples/", headers=AUTH)
        self.assertEqual(status, 200)
        self.assertEqual(data, {"projects": ["alpha", "beta"]})

        status, data, _ = self.request("GET", "/samples/alpha/", headers=AUTH)
        self.assertEqual(status, 200)
        self.assertEqual([(f["name"], f["size"]) for f in data["files"]], [("one.bin", 1), ("two.bin", 2)])
        self.assertEqual(data["files"][0]["path"], str(self.root / "alpha" / "one.bin"))

        status, _, _ = self.request("GET", "/samples/nope/", headers=AUTH)
        self.assertEqual(status, 404)

    def test_delete(self) -> None:
        self.request("PUT", "/samples/proj/a.bin", b"abc", AUTH)
        status, _, _ = self.request("DELETE", "/samples/proj/a.bin", headers=AUTH)
        self.assertEqual(status, 204)
        self.assertFalse((self.root / "proj" / "a.bin").exists())
        status, _, _ = self.request("DELETE", "/samples/proj/a.bin", headers=AUTH)
        self.assertEqual(status, 404)
        # The name is free again after a delete.
        status, _, _ = self.request("PUT", "/samples/proj/a.bin", b"new", AUTH)
        self.assertEqual(status, 201)


if __name__ == "__main__":
    unittest.main()
