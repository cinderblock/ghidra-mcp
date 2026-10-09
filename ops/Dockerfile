# syntax=docker/dockerfile:1
#
# One image for the ops deployment (cinderblock/ops, servers/sentinel/stacks/ghidra):
#
#   /app/entrypoint.sh            headless Ghidra server   (upstream, unchanged)
#   /opt/bridge/bin/bridge-mcp-ghidra   MCP bridge          (upstream python/, locked deps)
#   /app/samples_server.py        sample upload drop       (ops/, stdlib only)
#
# ops runs this one pinned image as three compose services with different
# entrypoints. Its stack loop pins exactly one image per stack, and this way
# the server, the bridge and the upload drop always come from the same reviewed
# commit.
#
# `server` is NOT a registry image: docker-bake.hcl builds upstream's own
# docker/Dockerfile as a sibling target and hands it in as a named context, so
# upstream's server build stays the single source of truth for that half.
FROM server

USER root

# The bridge needs a Python runtime; Ubuntu Noble (the temurin base) ships 3.12.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Install the bridge from uv.lock, not a fresh resolve: `uv sync --frozen`
# installs exactly the versions upstream tested, with their hashes. uv itself
# is mounted for this step only and never lands in the image. The source is
# copied to a scratch dir inside the same RUN (the bind mount is read-only and
# the wheel build writes), so no layer keeps it.
RUN --mount=from=ghcr.io/astral-sh/uv:0.12.24,source=/uv,target=/bin/uv \
    --mount=type=bind,target=/ctx \
    set -eux; \
    mkdir /tmp/bridge-src; \
    cp -r /ctx/pyproject.toml /ctx/uv.lock /ctx/README.md /ctx/python /tmp/bridge-src/; \
    cd /tmp/bridge-src; \
    UV_PROJECT_ENVIRONMENT=/opt/bridge UV_PYTHON_DOWNLOADS=never UV_COMPILE_BYTECODE=1 UV_NO_CACHE=1 \
        uv sync --frozen --no-default-groups --no-editable --python /usr/bin/python3; \
    cd /; \
    rm -rf /tmp/bridge-src; \
    /opt/bridge/bin/bridge-mcp-ghidra --help >/dev/null

COPY ops/samples_server.py /app/samples_server.py

# The two directories ops mounts named volumes onto, both under
# GHIDRA_MCP_FILE_ROOT=/work. Created here, owned by ghidra (uid 1000), because
# Docker seeds an EMPTY named volume with the mountpoint's ownership from the
# image — this is what makes a fresh volume writable by the non-root services.
RUN mkdir -p /work/projects /work/samples \
    && chown -R ghidra:ghidra /work \
    && chmod 0644 /app/samples_server.py

USER ghidra
