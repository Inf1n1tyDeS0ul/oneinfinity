# Contributing to One&Infinity

First off, thank you for considering contributing to One&Infinity! We welcome bug reports, feature requests, and pull requests.

## Development Setup
1. Clone the repository
2. Set up the Python virtual environment: `python3 -m venv .venv && source .venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Set up environment variables based on `.env.example`
5. Run tests locally before submitting a PR.

## Coding Standards
* Write clean, type-hinted Python code.
* Ensure no secrets, personal data, or client data is ever checked in.
* Write concise docstrings and document new features in `README.md` and `ARCHITECTURE.md`.
* Follow the existing architecture layout.

## Pull Requests
* Open an issue first to discuss major changes.
* Link the issue in your PR.
* Provide clear testing instructions and verify no regressions were introduced.
* All tests must pass (`python3 -m unittest discover -s tests -p "test_*.py"`) and the doctor health check must score `10.0/10.0`.

## Development with Docker

The distributed stack gives you a fully isolated environment without installing any Go tools or Python dependencies locally.

```bash
# First-time setup
make setup       # copies .env.example → .env, creates data/ dirs
# Edit .env and set ONEINFINITY_API_KEY

# Build and start the stack
make build
make up

# Tail logs
make logs

# Open a shell inside the orchestrator container
make shell

# Run a scan against a test target
make scan T=testphp.vulnweb.com

# Scale workers for faster scanning
make scale-recon N=3
make scale-vuln N=2

# Tear down when done
make down
```

When writing a new plugin, drop it into `plugins/community/<your-plugin>/plugin.py` — the `plugin-watcher` container hot-reloads the registry automatically. See [plugins/PLUGIN_SPEC.md](plugins/PLUGIN_SPEC.md) for the interface specification.

For changes to the worker or executor code, rebuild the worker image:

```bash
docker compose -f docker-compose.distributed.yml build worker-recon worker-vuln
make up
```

### Using Pre-Built Images from GHCR

If you are contributing documentation, tests, or non-tool changes, you can skip the local build entirely and pull the latest image from the GitHub Container Registry (GHCR):

```bash
# Pull core image
docker pull ghcr.io/inf1n1tydes0ul/oneinfinity:latest

# Pull AI-enabled image
docker pull ghcr.io/inf1n1tydes0ul/oneinfinity:latest-ai

# Run a single scan without starting the full docker compose stack
docker run --rm \
  -v ~/.oneinfinity:/data \
  -e ONEINFINITY_API_KEY=<your-key> \
  ghcr.io/inf1n1tydes0ul/oneinfinity:latest \
  scan testphp.vulnweb.com --yes
```

Images are published automatically by `.github/workflows/docker-publish.yml` on every push to `main` and on every semver tag. The `latest-ai` image variant includes AI/ML dependencies and is built with `INSTALL_AI=1`.

For local integration testing with the full distributed stack, use `docker-compose.distributed.yml` directly:

```bash
docker compose -f docker-compose.distributed.yml --profile monitoring up -d
docker compose -f docker-compose.distributed.yml ps
docker compose -f docker-compose.distributed.yml down
```