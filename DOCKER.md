# OneInfinity — Docker Guide

> Run the full OneInfinity offensive security platform without installing
> a single tool locally. Every Go binary, Python dependency, and system
> tool is pre-built into the image.

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [Image Variants](#2-image-variants)
3. [Building Locally](#3-building-locally)
4. [CLI Usage Reference](#4-cli-usage-reference)
5. [Real-World Pentesting Patterns](#5-real-world-pentesting-patterns)
6. [File Output & Volume Mounting](#6-file-output--volume-mounting)
7. [Networking Modes](#7-networking-modes)
8. [Permissions & Capabilities](#8-permissions--capabilities)
9. [Environment Variables](#9-environment-variables)
10. [Web UI with Docker Compose](#10-web-ui-with-docker-compose)
11. [GitHub Container Registry](#11-github-container-registry)
12. [Security Notes](#12-security-notes)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Quick Start

```bash
# Pull the latest image
docker pull ghcr.io/inf1n1tydes0ul/oneinfinity:latest

# Show all commands
docker run --rm -it ghcr.io/inf1n1tydes0ul/oneinfinity --help

# Basic scan
docker run --rm -it ghcr.io/inf1n1tydes0ul/oneinfinity scan example.com

# Check installed tools
docker run --rm ghcr.io/inf1n1tydes0ul/oneinfinity toolcheck
```

Alias for convenience (add to `~/.bashrc`):

```bash
alias oneinfinity='docker run --rm -it \
  --network host \
  --cap-add=NET_RAW \
  -v $(pwd)/oi-data:/data \
  -e GITHUB_TOKEN \
  -e OPENAI_API_KEY \
  ghcr.io/inf1n1tydes0ul/oneinfinity'
```

Then use it exactly like the native CLI:

```bash
oneinfinity scan example.com
oneinfinity recon example.com
oneinfinity research example.com --yes --active
```

---

## 2. Image Variants

| Tag | Size | Includes |
|-----|------|----------|
| `latest` | ~1.8 GB | Core CLI + all Go tools + system tools |
| `latest-ai` | ~3.2 GB | Everything in `latest` + AI/ML red-team libs |
| `sha-XXXXXXX` | same as latest | Exact commit build — pinned for reproducibility |
| `1.x.x` | same as latest | Semver-pinned release |

**Choose your variant:**

```bash
# Core — all pentesting features (recommended for most use cases)
docker pull ghcr.io/inf1n1tydes0ul/oneinfinity:latest

# AI — adds ai-test, ai-redteam, ai-agent-test
docker pull ghcr.io/inf1n1tydes0ul/oneinfinity:latest-ai

# Pinned release (reproducible engagements)
docker pull ghcr.io/inf1n1tydes0ul/oneinfinity:1.1.0
```

---

## 3. Building Locally

### Standard build

```bash
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity
docker build -t oneinfinity .
```

### With AI/ML dependencies

```bash
docker build \
  --build-arg INSTALL_AI=1 \
  -t oneinfinity:ai .
```

### With mobile analysis dependencies

```bash
docker build \
  --build-arg INSTALL_MOBILE=1 \
  -t oneinfinity:mobile .
```

### Full-featured (AI + mobile)

```bash
docker build \
  --build-arg INSTALL_AI=1 \
  --build-arg INSTALL_MOBILE=1 \
  -t oneinfinity:full .
```

### Build with custom Python version

```bash
# Use Python 3.10 for maximum giskard compatibility
docker build \
  --build-arg PYTHON_VERSION=3.10 \
  --build-arg INSTALL_AI=1 \
  -t oneinfinity:ai-py310 .
```

### Build cache — speed up repeated builds

```bash
# First build: populate cache
docker build --cache-from oneinfinity:latest -t oneinfinity .

# Subsequent builds use layer cache automatically
```

---

## 4. CLI Usage Reference

Every `oneinfinity` command works identically inside Docker.
The general pattern is:

```bash
docker run [DOCKER_FLAGS] ghcr.io/inf1n1tydes0ul/oneinfinity [COMMAND] [ARGS]
```

### Minimal (no persistence, no networking tricks)

```bash
docker run --rm -it ghcr.io/inf1n1tydes0ul/oneinfinity <command>
```

### With output persistence

```bash
docker run --rm -it \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity <command>
```

### Full pentesting mode

```bash
docker run --rm -it \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v $(pwd)/output:/data \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  ghcr.io/inf1n1tydes0ul/oneinfinity <command>
```

---

## 5. Real-World Pentesting Patterns

### Workspace setup

```bash
docker run --rm -it -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  setup vulnbank-engagement --target vulnbank.org
```

### Full recon

```bash
docker run --rm -it \
  --network host \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  recon vulnbank.org
```

### Adaptive recon (tech-aware)

```bash
docker run --rm -it \
  --network host \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  adaptive-recon vulnbank.org --depth deep
```

### Vulnerability scan

```bash
docker run --rm -it \
  --network host \
  --cap-add=NET_RAW \
  -v $(pwd)/output:/data \
  -e OOB_DOMAIN="your-collaborator.burpcollaborator.net" \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  vuln-scan vulnbank.org \
    --severity medium,high,critical \
    --oob "${OOB_DOMAIN}"
```

### Autonomous research mode

```bash
docker run --rm -it \
  --network host \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  research vulnbank.org \
    --yes \
    --active \
    --iterations 5
```

### Secret scanning (GitHub org)

```bash
docker run --rm -it \
  -v $(pwd)/output:/data \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  secrets-scan \
    --target vulnbank \
    --mode thorough \
    --adaptive-throttle
```

### AI red team (requires :latest-ai image)

```bash
docker run --rm -it \
  --network host \
  -v $(pwd)/output:/data \
  -e OPENAI_API_KEY="${OPENAI_API_KEY}" \
  ghcr.io/inf1n1tydes0ul/oneinfinity:latest-ai \
  ai-redteam http://target.com \
    --campaign jailbreak \
    --prompts 200 \
    --evolve \
    --yes
```

### Exploit chain detection + PoC generation

```bash
docker run --rm -it \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  chains vulnbank.org
```

### Generate report

```bash
docker run --rm \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  report --all
```

### Mobile APK analysis

```bash
# Copy APK into output dir first so the container can see it
cp target.apk ./output/

docker run --rm -it \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  mobile-analyze /data/target.apk \
    --output /data/mobile-results
```

### Multi-target swarm scan

```bash
# Write targets to a file
echo -e "example.com\napp.example.com\napi.example.com" > targets.txt

docker run --rm -it \
  --network host \
  -v $(pwd)/output:/data \
  -v $(pwd)/targets.txt:/targets.txt:ro \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  swarm /targets.txt --workers 20 --yes
```

### Autonomous bug bounty hunter

```bash
docker run --rm -it \
  --network host \
  -v $(pwd)/output:/data \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  hunter-start \
    --platforms hackerone \
    --max-targets 10 \
    --yes
```

### Interactive shell (debugging)

```bash
docker run --rm -it \
  --network host \
  --cap-add=NET_RAW \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  shell
```

---

## 6. File Output & Volume Mounting

All scan output, SQLite databases, and recon data are written to
`/data` inside the container (controlled by the `ONEINFINITY_HOME`
environment variable).

### Map output to your current directory

```bash
-v $(pwd)/output:/data
```

After the scan, your output is at `./output/`:

```
output/
├── raw/
│   └── vulnbank.org/
│       ├── recon/
│       │   ├── subdomains.json
│       │   ├── alive_hosts.json
│       │   ├── urls.json
│       │   └── tech_profile.json
│       ├── app_model.json
│       └── research_summary.json
├── findings.db          ← SQLite findings database
├── knowledge_base.db    ← Learnings across sessions
└── recon_cache.db       ← Cached recon data
```

### Named Docker volume (persistent across runs)

```bash
# Create a named volume
docker volume create oi-data

# Use it on every run
docker run --rm -it \
  -v oi-data:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  research example.com --yes
```

### Read findings from a previous scan

```bash
# All findings
docker run --rm -it -v oi-data:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity findings list

# Export as JSON to host
docker run --rm -v oi-data:/data -v $(pwd):/export \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  findings export json
# Result: /export/findings.json (or wherever oneinfinity writes it)
```

### Mount custom wordlists

```bash
docker run --rm -it \
  -v $(pwd)/wordlists:/wordlists:ro \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  fuzz example.com
```

---

## 7. Networking Modes

### Default bridge (isolated)

Suitable for most web scanning. DNS resolution and outbound HTTP work.

```bash
docker run --rm -it ghcr.io/inf1n1tydes0ul/oneinfinity scan example.com
```

### Host networking (recommended for pentesting)

Required for:
- Raw socket operations (nmap SYN scan, masscan)
- Accessing hosts on the same LAN
- Avoiding NAT overhead during high-speed scanning

```bash
docker run --rm -it --network host ghcr.io/inf1n1tydes0ul/oneinfinity \
  vuln-scan example.com
```

> **Note:** `--network host` only works on Linux hosts.
> On macOS/Windows, use a Linux VM or Docker Desktop in a Linux context.

### Through Burp Suite proxy

```bash
docker run --rm -it \
  --network host \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  proxy-set http://127.0.0.1:8080 --scope all

# Then run your scan — all traffic routes through Burp
docker run --rm -it \
  --network host \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  vuln-scan example.com
```

### Through a SOCKS5 proxy

```bash
docker run --rm -it \
  --network host \
  -e ALL_PROXY=socks5://127.0.0.1:1080 \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  recon example.com
```

---

## 8. Permissions & Capabilities

The container runs as the `oi` user (non-root) by default.
Some tools require elevated capabilities:

| Tool | Capability Needed | Flag |
|------|------------------|------|
| `nmap` SYN scan | `NET_RAW` | `--cap-add=NET_RAW` |
| `masscan` | `NET_RAW` + `NET_ADMIN` | both caps |
| `naabu` (SYN mode) | `NET_RAW` | `--cap-add=NET_RAW` |
| `rustscan` | none (uses connect scan) | — |

### Standard pentesting run (recommended)

```bash
docker run --rm -it \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  <command>
```

### Privileged mode (last resort)

Only use if specific capabilities still cause issues. Grants full host kernel access.

```bash
# ⚠️  USE WITH CAUTION — grants all Linux capabilities
docker run --rm -it --privileged \
  --network host \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  <command>
```

### Running as root inside container

If a tool strictly requires UID 0:

```bash
docker run --rm -it --user root \
  --network host \
  --cap-add=NET_RAW \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  <command>
```

---

## 9. Environment Variables

Pass credentials and configuration via `-e` flags:

| Variable | Required? | Description |
|----------|-----------|-------------|
| `ONEINFINITY_HOME` | No | Data dir inside container. Default: `/data` |
| `GITHUB_TOKEN` | For secret scanning | GitHub PAT with `repo` scope |
| `OPENAI_API_KEY` | For AI testing | OpenAI-compatible API key |
| `ONEINFINITY_API_KEY` | For Web UI | Backend API auth key |
| `NUCLEI_UPDATE` | No | Set `0` to skip nuclei template update (offline mode) |
| `OOB_DOMAIN` | For blind vulns | OOB callback domain (Burp Collaborator, interactsh) |
| `ALL_PROXY` | No | Route all traffic through a proxy |
| `GITHUB_TOKEN` | No | Multi-token: comma-separated in secrets-scan |

### Passing secrets securely

**Option 1 — Environment inheritance (recommended):**

```bash
# Set in your shell session
export GITHUB_TOKEN="ghp_..."
export OPENAI_API_KEY="sk-..."

# Pass to container without printing the values
docker run --rm -it \
  -e GITHUB_TOKEN \
  -e OPENAI_API_KEY \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  secrets-scan --target myorg
```

**Option 2 — .env file:**

```bash
# .env (never commit this file)
GITHUB_TOKEN=ghp_...
OPENAI_API_KEY=sk-...

docker run --rm -it \
  --env-file .env \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  secrets-scan --target myorg
```

**Option 3 — Docker secrets (production/CI):**

```bash
# Create secret
echo "ghp_..." | docker secret create github_token -

# Use in compose (swarm mode)
# secrets:
#   github_token:
#     external: true
```

---

## 10. Web UI with Docker Compose

Start the full platform (CLI + backend API + React dashboard):

```bash
# Clone and configure
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity
cp .env.example .env  # edit with your keys

# Start everything
docker compose --profile full up

# Access:
#   Dashboard:  http://localhost:3000
#   API:        http://localhost:8000
#   API docs:   http://localhost:8000/docs
```

**Run a scan from within the running stack:**

```bash
docker compose run --rm cli research vulnbank.org --yes
```

**View live findings while scanning:**

```bash
# Terminal 1 — start the scan
docker compose run --rm cli research vulnbank.org --yes

# Terminal 2 — tail findings in real time
docker compose run --rm cli findings list
```

**Stop everything:**

```bash
docker compose --profile full down
```

---

## 11. GitHub Container Registry

### Manual push

```bash
# Authenticate
echo "${GITHUB_TOKEN}" | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Build
docker build -t oneinfinity .

# Tag
docker tag oneinfinity ghcr.io/inf1n1tydes0ul/oneinfinity:latest
docker tag oneinfinity ghcr.io/inf1n1tydes0ul/oneinfinity:1.1.0

# Push
docker push ghcr.io/inf1n1tydes0ul/oneinfinity:latest
docker push ghcr.io/inf1n1tydes0ul/oneinfinity:1.1.0
```

### Automated CI/CD

The included `.github/workflows/docker-publish.yml` automatically:

| Event | Action |
|-------|--------|
| Push to `main` | Builds and pushes `:latest` + `:sha-XXXXXXX` |
| Push tag `v1.2.3` | Builds and pushes `:1.2.3`, `:1.2`, `:1`, `:latest` |
| Pull request | Build only (validates Dockerfile, no push) |
| Manual dispatch | Optionally builds the AI variant |

**Enable the workflow:**

1. Go to your repo → Settings → Actions → General
2. Allow GitHub Actions to create and approve pull requests
3. The `GITHUB_TOKEN` secret is automatically available

**Make package public** (so anyone can `docker pull`):

1. Go to `https://github.com/users/Inf1n1tyDeS0ul/packages`
2. Click on `oneinfinity` package → Package settings
3. Change visibility to **Public**

### Multi-architecture build

The workflow builds for both `linux/amd64` (Intel/AMD) and `linux/arm64`
(Apple Silicon M1/M2/M3, AWS Graviton). Images run natively on both platforms.

```bash
# Verify image platforms
docker manifest inspect ghcr.io/inf1n1tydes0ul/oneinfinity:latest
```

---

## 12. Security Notes

### Image trust

- All images are built via GitHub Actions with SBOM attestation
- Verify image signature:

```bash
# Install cosign
brew install cosign  # macOS

# Verify
cosign verify \
  --certificate-identity "https://github.com/Inf1n1tyDeS0ul/oneinfinity/.github/workflows/docker-publish.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/inf1n1tydes0ul/oneinfinity:latest
```

### Minimal capabilities principle

Always use the minimum capabilities required:

```bash
# ✅ Good — only adds what's needed for port scanning
docker run --cap-add=NET_RAW oneinfinity nmap-scan example.com

# ❌ Bad — grants everything (avoid unless absolutely necessary)
docker run --privileged oneinfinity nmap-scan example.com
```

### Secret isolation

Never bake secrets into images:

```bash
# ❌ Bad
docker build --build-arg GITHUB_TOKEN=ghp_... .

# ✅ Good — pass at runtime
docker run -e GITHUB_TOKEN="${GITHUB_TOKEN}" oneinfinity secrets-scan --target org
```

### Network isolation

When scanning internal targets, use a specific network rather than `--network host`:

```bash
# Create an isolated network for the scan
docker network create --driver bridge scan-net

docker run --rm -it \
  --network scan-net \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  recon 192.168.1.0/24
```

### Scan authorization

> The `--network host` flag and capabilities like `NET_RAW` give the container
> the same network access as the host. Only scan targets you have explicit
> written authorization to test.

---

## 13. Troubleshooting

### `permission denied` writing to /data

The `oi` user (UID 999) must own the host directory:

```bash
# Fix ownership
sudo chown -R 999:999 ./output

# Or run as current user
docker run --rm -it \
  --user $(id -u):$(id -g) \
  -v $(pwd)/output:/data \
  ghcr.io/inf1n1tydes0ul/oneinfinity scan example.com
```

### `nuclei: executable file not found in $PATH`

Nuclei (and other Go binaries) live in `/go-bins/` which is on `PATH`
inside the container. If you see this error with a custom image:

```bash
# Verify Go bins are present
docker run --rm ghcr.io/inf1n1tydes0ul/oneinfinity shell -c "ls /go-bins/"

# Check PATH
docker run --rm ghcr.io/inf1n1tydes0ul/oneinfinity shell -c "echo $PATH"
```

### `nmap: Operation not permitted` (raw sockets)

Add the `NET_RAW` capability:

```bash
docker run --rm -it --cap-add=NET_RAW \
  --network host \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  vuln-scan example.com
```

### Nuclei template download fails (offline / air-gapped)

```bash
# Skip template update
docker run --rm -it \
  -e NUCLEI_UPDATE=0 \
  ghcr.io/inf1n1tydes0ul/oneinfinity scan example.com

# Or pre-populate templates via a named volume
docker run --rm \
  -v oi-templates:/data/.nuclei-templates \
  ghcr.io/inf1n1tydes0ul/oneinfinity \
  shell -c "nuclei -update-templates -update-template-dir /data/.nuclei-templates"
```

### `--network host` not working on macOS/Windows

Docker Desktop on macOS/Windows runs containers inside a Linux VM.
`--network host` attaches the container to the VM's network, not the
host OS network. Options:

1. Use a Linux VM (VirtualBox/UTM) and run Docker there
2. Use Docker Desktop's `host-gateway` feature for specific ports
3. For most web scanning (no raw sockets), bridge mode works fine

### `giskard` / AI deps not available

The `latest` image does not include heavy AI deps. Use the AI variant:

```bash
docker pull ghcr.io/inf1n1tydes0ul/oneinfinity:latest-ai
# or build locally:
docker build --build-arg INSTALL_AI=1 -t oneinfinity:ai .
```

### Build fails at Go tools stage

Some Go tools have intermittent network issues during `go install`.
Retry the build with `--no-cache` to force fresh downloads:

```bash
docker build --no-cache -t oneinfinity .
```

Or use the GitHub Actions pre-built image which has all tools already compiled.
