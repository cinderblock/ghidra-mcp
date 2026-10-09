# Builds the ops image: upstream's headless server (docker/Dockerfile) as the
# base, with the MCP bridge and the sample upload drop layered on by
# ops/Dockerfile. Run from the repository root:
#
#   docker buildx bake -f ops/docker-bake.hcl image
#
# CI (.github/workflows/ops-image.yml) sets IMAGE and REVISION and pushes.

variable "IMAGE" {
  default = "ghidra-mcp-ops"
}

variable "REVISION" {
  default = "dev"
}

variable "SOURCE" {
  default = "https://github.com/cinderblock/ghidra-mcp"
}

# Upstream's server image, unmodified. Not pushed on its own; it only exists
# to be the `server` context below.
target "server" {
  context    = "."
  dockerfile = "docker/Dockerfile"
}

target "image" {
  context    = "."
  dockerfile = "ops/Dockerfile"
  contexts = {
    server = "target:server"
  }
  tags = [
    "${IMAGE}:${REVISION}",
    "${IMAGE}:latest",
  ]
  # ops verifies the revision label against the commit its pin.json claims;
  # the deploy fails without it.
  labels = {
    "org.opencontainers.image.revision" = REVISION
    "org.opencontainers.image.source"   = SOURCE
    "org.opencontainers.image.licenses" = "Apache-2.0"
  }
}
