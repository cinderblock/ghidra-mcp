# ops branch: the image cinderblock/ops runs

This fork of [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp)
exists to publish one container image for
[cinderblock/ops](https://github.com/cinderblock/ops)
(`servers/sentinel/stacks/ghidra/`). Everything specific to that lives in `ops/`
and `.github/workflows/ops-image.yml`. Nothing upstream is modified.

| File                            | What                                                                                |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| `ops/Dockerfile`                | Adds the MCP bridge (from `uv.lock`) and the upload drop to upstream's server image |
| `ops/docker-bake.hcl`           | Builds upstream's `docker/Dockerfile` and feeds it to the above as `server`         |
| `ops/samples_server.py`         | `PUT /samples/<project>/<name>`: puts binaries where `import_file` can see them      |
| `ops/test_samples_server.py`    | Its tests (`python3 -m unittest discover -s ops`)                                    |
| `.github/workflows/ops-image.yml` | Tests, builds, pushes `ghcr.io/cinderblock/ghidra-mcp:<sha>`, prints a `pin.json` |

## Shipping

1. Push `ops` here. CI publishes the image and prints a ready-to-paste `pin.json`.
2. Paste it into `servers/sentinel/stacks/ghidra/pin.json` in ops and push ops.

## Taking upstream changes

Merge, never rebase. A rebase rewrites published commits and would need a
force-push:

```sh
git fetch upstream
git switch ops
git merge upstream/main   # or a specific tag/commit
git push
```

Upstream's default branch is `dev`. `main` is what it releases from, and it's
what `ops` tracks.

Keep `docker/Dockerfile`'s `GHIDRA_VERSION` in mind when merging. It decides
which Ghidra the image ships, and projects saved by a newer Ghidra can't be
opened by an older one.

## Upstream workflows

They're disabled in this fork (`gh workflow disable`). They target upstream's
branches and infrastructure (including a self-hosted Windows runner), and
nothing here needs them.
