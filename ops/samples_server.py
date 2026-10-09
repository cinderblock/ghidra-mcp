#!/usr/bin/env python3
"""Sample drop for the ops deployment of ghidra-mcp.

The headless Ghidra server imports binaries by *path on its own filesystem*
(`/import_file`); it has no upload endpoint. This is the missing half: a small
HTTP service, no UI, that writes uploaded binaries into a directory the Ghidra
container mounts read-only, and answers with the path to hand `import_file`.

    PUT    /samples/<project>/<name>   raw body -> 201 {"path", "sha256", "size"}
                                       same bytes again -> 200 (idempotent)
                                       different bytes  -> 409 (never overwrites)
    DELETE /samples/<project>/<name>   -> 204
    GET    /samples/                   -> {"projects": [...]}
    GET    /samples/<project>/         -> {"files": [...]}
    GET    /healthz                    -> 200, no auth (container healthcheck)

Every other request needs `Authorization: Bearer $GHIDRA_MCP_AUTH_TOKEN`, the
same token the bridge and the Ghidra server take.

Names are restricted to [A-Za-z0-9._-] and must start with an alphanumeric, so
a name can never be a path, a traversal, or a dotfile (the in-flight temp files
are dotfiles, which is what keeps them out of listings).

Standard library only, so the image needs nothing installed for it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import signal
import sys
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

PREFIX = "/samples"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
TEMP_PREFIX = ".upload-"
CHUNK = 1 << 20


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(CHUNK):
            digest.update(block)
    return digest.hexdigest()


class SamplesHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 so curl's `Expect: 100-continue` on large uploads is answered
    # by the stdlib (handle_expect_100) instead of stalling for a second.
    protocol_version = "HTTP/1.1"
    server_version = "ghidra-samples"
    sys_version = ""

    # Set by make_server().
    root: Path
    expected_auth: bytes
    max_bytes: int

    # --- plumbing -----------------------------------------------------------

    def _send_json(self, status: HTTPStatus, body: dict | None = None, headers: dict | None = None) -> None:
        payload = b"" if body is None else json.dumps(body, indent=2).encode("utf-8") + b"\n"
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if payload and self.command != "HEAD":
            self.wfile.write(payload)

    def _error(self, status: HTTPStatus, message: str, *, close: bool = False, headers: dict | None = None) -> None:
        # An early answer to an upload we did not read leaves the body on the
        # socket; reusing the connection would parse it as the next request.
        if close:
            self.close_connection = True
            headers = {**(headers or {}), "Connection": "close"}
        self._send_json(status, {"error": message}, headers)

    def _authorized(self) -> bool:
        supplied = (self.headers.get("Authorization") or "").encode("utf-8")
        return hmac.compare_digest(supplied, self.expected_auth)

    def _segments(self) -> list[str] | None:
        """Path segments under /samples, or None if the path is not ours.

        Deliberately not percent-decoded: every legal name is plain ASCII, so a
        `%` can only be an attempt to smuggle a `/` or `..` past the check.
        """
        path = urlsplit(self.path).path
        if path != PREFIX and not path.startswith(PREFIX + "/"):
            return None
        segments = [s for s in path[len(PREFIX):].split("/") if s]
        if any(not NAME.fullmatch(s) for s in segments):
            return None
        return segments

    def _route(self, allow_unread_body: bool = False) -> list[str] | None:
        """Authenticate and resolve the path; on failure, answer and return None."""
        if not self._authorized():
            self._error(HTTPStatus.UNAUTHORIZED, "missing or wrong bearer token",
                        close=allow_unread_body, headers={"WWW-Authenticate": "Bearer"})
            return None
        segments = self._segments()
        if segments is None:
            self._error(HTTPStatus.NOT_FOUND,
                        "not found; names must match [A-Za-z0-9][A-Za-z0-9._-]{0,199}",
                        close=allow_unread_body)
            return None
        return segments

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        forwarded = self.headers.get("X-Forwarded-For") if hasattr(self, "headers") and self.headers else None
        who = forwarded or self.address_string()
        sys.stderr.write(f"{who} - {format % args}\n")

    # --- methods ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if urlsplit(self.path).path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        segments = self._route()
        if segments is None:
            return
        if len(segments) == 0:
            projects = sorted(
                p.name for p in self.root.iterdir() if p.is_dir() and NAME.fullmatch(p.name)
            ) if self.root.is_dir() else []
            self._send_json(HTTPStatus.OK, {"projects": projects})
        elif len(segments) == 1:
            project_dir = self.root / segments[0]
            if not project_dir.is_dir():
                self._error(HTTPStatus.NOT_FOUND, f"no project {segments[0]!r}")
                return
            files = []
            for entry in sorted(project_dir.iterdir()):
                if entry.is_file() and NAME.fullmatch(entry.name):
                    files.append({"name": entry.name, "path": str(entry), "size": entry.stat().st_size})
            self._send_json(HTTPStatus.OK, {"project": segments[0], "files": files})
        else:
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "GET lists a project; PUT or DELETE a file",
                        headers={"Allow": "PUT, DELETE"})

    def do_PUT(self) -> None:  # noqa: N802
        segments = self._route(allow_unread_body=True)
        if segments is None:
            return
        if len(segments) != 2:
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "PUT /samples/<project>/<name>", close=True,
                        headers={"Allow": "GET"})
            return
        if self.headers.get("Transfer-Encoding"):
            self._error(HTTPStatus.LENGTH_REQUIRED, "chunked uploads are not accepted; send Content-Length",
                        close=True)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._error(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required", close=True)
            return
        if length < 0:
            self._error(HTTPStatus.BAD_REQUEST, "negative Content-Length", close=True)
            return
        if length > self.max_bytes:
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        f"{length} bytes is over the {self.max_bytes}-byte limit", close=True)
            return

        project, name = segments
        project_dir = self.root / project
        project_dir.mkdir(mode=0o755, exist_ok=True)
        target = project_dir / name

        fd, temp_name = tempfile.mkstemp(dir=project_dir, prefix=TEMP_PREFIX)
        temp = Path(temp_name)
        try:
            digest = hashlib.sha256()
            remaining = length
            with os.fdopen(fd, "wb") as out:
                while remaining:
                    block = self.rfile.read(min(CHUNK, remaining))
                    if not block:
                        break
                    digest.update(block)
                    out.write(block)
                    remaining -= len(block)
                out.flush()
                os.fsync(out.fileno())
            if remaining:
                self._error(HTTPStatus.BAD_REQUEST,
                            f"body ended {remaining} bytes short of Content-Length", close=True)
                return
            os.chmod(temp, 0o644)
            sha256 = digest.hexdigest()
            result = {"project": project, "name": name, "path": str(target), "size": length, "sha256": sha256}

            # link() refuses to replace an existing name, so two racing uploads
            # of one name cannot clobber each other: exactly one wins.
            try:
                os.link(temp, target)
            except FileExistsError:
                existing = _sha256_of(target)
                if existing == sha256:
                    self._send_json(HTTPStatus.OK, {**result, "existing": True})
                else:
                    self._error(HTTPStatus.CONFLICT,
                                f"{project}/{name} already exists with different content "
                                f"(sha256 {existing}); pick another name or DELETE it first")
                return
            self._send_json(HTTPStatus.CREATED, {**result, "existing": False})
        finally:
            temp.unlink(missing_ok=True)

    def do_DELETE(self) -> None:  # noqa: N802
        segments = self._route()
        if segments is None:
            return
        if len(segments) != 2:
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "DELETE /samples/<project>/<name>",
                        headers={"Allow": "GET"})
            return
        target = self.root / segments[0] / segments[1]
        try:
            target.unlink()
        except FileNotFoundError:
            self._error(HTTPStatus.NOT_FOUND, f"no file {segments[0]}/{segments[1]}")
            return
        self._send_json(HTTPStatus.NO_CONTENT)


def remove_stale_uploads(root: Path) -> None:
    """Drop temp files a crash or a killed container left mid-upload."""
    if not root.is_dir():
        return
    for project_dir in root.iterdir():
        if project_dir.is_dir():
            for stale in project_dir.glob(TEMP_PREFIX + "*"):
                stale.unlink(missing_ok=True)


def make_server(host: str, port: int, root: Path, token: str, max_bytes: int) -> ThreadingHTTPServer:
    if not token:
        raise ValueError("an auth token is required")
    root.mkdir(parents=True, exist_ok=True)
    remove_stale_uploads(root)
    handler = type("ConfiguredSamplesHandler", (SamplesHandler,), {
        "root": root,
        "expected_auth": f"Bearer {token}".encode("utf-8"),
        "max_bytes": max_bytes,
    })
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def main() -> None:
    token = os.environ.get("GHIDRA_MCP_AUTH_TOKEN", "").strip()
    if not token:
        sys.exit("GHIDRA_MCP_AUTH_TOKEN is required; refusing to serve uploads without auth")
    root = Path(os.environ.get("SAMPLES_DIR", "/work/samples"))
    host = os.environ.get("SAMPLES_HOST", "0.0.0.0")
    port = int(os.environ.get("SAMPLES_PORT", "9082"))
    max_bytes = int(os.environ.get("SAMPLES_MAX_BYTES", str(2 * 1024 ** 3)))

    server = make_server(host, port, root, token, max_bytes)
    # PID 1 in a container ignores SIGTERM unless it installs a handler, which
    # would turn every `docker stop` into a 10-second wait and a SIGKILL.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print(f"ghidra-samples: serving {root} on {host}:{port} (max {max_bytes} bytes)", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
