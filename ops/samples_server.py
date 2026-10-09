#!/usr/bin/env python3
"""Sample drop for the ops deployment of ghidra-mcp.

The headless Ghidra server loads binaries by *path on its own filesystem*
(`/load_program`); it has no upload endpoint. This is the missing half: a small
HTTP service, no UI, that writes uploaded binaries into a directory the Ghidra
container mounts read-only, and answers with the path to hand `load_program`.
(The bridge's `import_file` tool is GUI-only; headless it refuses.)

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

import errno
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
# A rejected upload's body is read and dropped up to this size, so the
# connection can end cleanly; anything bigger is cut off instead.
DRAIN_LIMIT = 1 << 20
NAME_HINT = "not found; names must match [A-Za-z0-9][A-Za-z0-9._-]{0,199}"


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
        if close:
            self.close_connection = True
            headers = {**(headers or {}), "Connection": "close"}
        self._send_json(status, {"error": message}, headers)

    def _drain_body(self) -> bool:
        """Read and drop a small request body. False if it wasn't (fully) drained."""
        if self.headers.get("Transfer-Encoding"):
            return False
        try:
            remaining = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return False
        if not 0 <= remaining <= DRAIN_LIMIT:
            return False
        while remaining:
            block = self.rfile.read(min(CHUNK, remaining))
            if not block:
                return False
            remaining -= len(block)
        return True

    def _reject_upload(self, status: HTTPStatus, message: str, headers: dict, *, body_sent: bool) -> None:
        """Answer a PUT whose body we will not keep.

        A small body is read and dropped first, so the connection ends cleanly.
        Closing a socket that still has unread data makes the kernel send a
        reset, and the reset can overtake this response, leaving the client
        with "connection reset" instead of the reason (seen on Windows in the
        tests). A large body isn't worth reading, so the connection closes and
        is never reused: the leftover bytes would parse as the next request.
        `body_sent=False` means the client is waiting on `Expect:
        100-continue` and hasn't sent the body, so there is nothing to drain.
        """
        drained = body_sent and self._drain_body()
        self._error(status, message, headers=headers, close=not drained)

    def _put_rejection(self) -> tuple[HTTPStatus, str, dict] | None:
        """Why this PUT cannot succeed, judged from its headers alone; None if it can."""
        if not self._authorized():
            return HTTPStatus.UNAUTHORIZED, "missing or wrong bearer token", {"WWW-Authenticate": "Bearer"}
        segments = self._segments()
        if segments is None:
            return HTTPStatus.NOT_FOUND, NAME_HINT, {}
        if len(segments) != 2:
            return HTTPStatus.METHOD_NOT_ALLOWED, "PUT /samples/<project>/<name>", {"Allow": "GET"}
        if self.headers.get("Transfer-Encoding"):
            return HTTPStatus.LENGTH_REQUIRED, "chunked uploads are not accepted; send Content-Length", {}
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return HTTPStatus.LENGTH_REQUIRED, "Content-Length is required", {}
        if length < 0:
            return HTTPStatus.BAD_REQUEST, "negative Content-Length", {}
        if length > self.max_bytes:
            return HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"{length} bytes is over the {self.max_bytes}-byte limit", {}
        return None

    def handle_expect_100(self) -> bool:
        # Turn a doomed upload away before the client sends it: answering with
        # the final status instead of 100 Continue is what Expect is for, and
        # curl sends it for any body over 1 MiB.
        if self.command == "PUT" and (rejection := self._put_rejection()):
            self._reject_upload(*rejection, body_sent=False)
            return False
        return super().handle_expect_100()

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

    def _route(self) -> list[str] | None:
        """Authenticate and resolve the path of a bodiless request; on failure, answer and return None."""
        if not self._authorized():
            self._error(HTTPStatus.UNAUTHORIZED, "missing or wrong bearer token",
                        headers={"WWW-Authenticate": "Bearer"})
            return None
        segments = self._segments()
        if segments is None:
            self._error(HTTPStatus.NOT_FOUND, NAME_HINT)
            return None
        return segments

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        forwarded = self.headers.get("X-Forwarded-For") if hasattr(self, "headers") and self.headers else None
        who = forwarded or self.address_string()
        sys.stderr.write(f"{who} - {format % args}\n")

    # --- methods ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if urlsplit(self.path).path == "/healthz":
            # Writability is the thing that actually breaks: a named volume
            # seeded root-owned (by whichever container mounted it first)
            # serves listings fine and fails every upload.
            if os.access(self.root, os.W_OK | os.X_OK):
                self._send_json(HTTPStatus.OK, {"status": "ok"})
            else:
                self._error(HTTPStatus.SERVICE_UNAVAILABLE, f"{self.root} is not writable by this service")
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
        if rejection := self._put_rejection():
            self._reject_upload(*rejection, body_sent=True)
            return
        project, name = self._segments()
        length = int(self.headers["Content-Length"])

        project_dir = self.root / project
        project_dir.mkdir(mode=0o755, exist_ok=True)
        target = project_dir / name

        # The response goes out only after the temp file is gone, so a client
        # that lists the project right after an answer never sees it.
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
                outcome = HTTPStatus.BAD_REQUEST, f"body ended {remaining} bytes short of Content-Length"
            else:
                os.chmod(temp, 0o644)
                sha256 = digest.hexdigest()
                result = {"project": project, "name": name, "path": str(target), "size": length, "sha256": sha256}
                # link() refuses to replace an existing name, so two racing
                # uploads of one name cannot clobber each other: one wins.
                try:
                    os.link(temp, target)
                    outcome = HTTPStatus.CREATED, {**result, "existing": False}
                except FileExistsError:
                    existing = _sha256_of(target)
                    if existing == sha256:
                        outcome = HTTPStatus.OK, {**result, "existing": True}
                    else:
                        outcome = HTTPStatus.CONFLICT, (
                            f"{project}/{name} already exists with different content "
                            f"(sha256 {existing}); pick another name or DELETE it first")
        finally:
            temp.unlink(missing_ok=True)

        status, body = outcome
        if isinstance(body, dict):
            self._send_json(status, body)
        else:
            # A short body means the stream is out of step; never reuse it.
            self._error(status, body, close=status == HTTPStatus.BAD_REQUEST)

    def do_DELETE(self) -> None:  # noqa: N802
        segments = self._route()
        if segments is None:
            return
        if len(segments) != 2:
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "DELETE /samples/<project>/<name>",
                        headers={"Allow": "GET"})
            return
        project_dir = self.root / segments[0]
        try:
            (project_dir / segments[1]).unlink()
        except FileNotFoundError:
            self._error(HTTPStatus.NOT_FOUND, f"no file {segments[0]}/{segments[1]}")
            return
        # The last file out takes its project folder with it, so finished
        # projects stop showing up in GET /samples/. Anything still in there
        # (another file, or an upload in flight) keeps it.
        if not any(project_dir.iterdir()):
            try:
                project_dir.rmdir()
            except OSError as e:
                if e.errno not in (errno.ENOTEMPTY, errno.EEXIST, errno.ENOENT):
                    raise
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
