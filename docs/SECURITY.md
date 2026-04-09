# Security Policy

## Supported Versions
Only the latest version (`v1.0.0` or `main` branch) is actively supported with security updates.

## Reporting a Vulnerability
We take the security of One&Infinity seriously. If you discover a vulnerability, please DO NOT report it by opening a public GitHub issue. 
Instead, please send an email privately with details of the vulnerability. We will endeavor to respond quickly.

When reporting:
* Describe the vulnerability, its impact, and steps to reproduce.
* If possible, provide a proof of concept.

Thank you for helping keep the open-source community secure!

## Docker Security Posture

The distributed Docker stack is designed with the following security controls:

| Control | Implementation |
|---|---|
| Non-root user | All containers run as `oi` (UID 1000) — not root |
| Minimal capabilities | Workers add only `NET_RAW` + `NET_ADMIN` (required for nmap/masscan/naabu); orchestrator and frontend have no extra capabilities |
| Secret handling | API keys and tokens are passed via `.env` file — never baked into images; `.env` is in `.gitignore` and `.dockerignore` |
| Image provenance | Production images are built via GitHub Actions and pushed to GHCR with SHA-pinned base images |
| Redis hardening | `FLUSHALL`, `FLUSHDB`, and `DEBUG` commands are disabled in `services/redis/redis.conf`; Redis is not exposed externally by default |
| Network isolation | Services communicate on the `internal` bridge network (172.28.0.0/16); only nginx is on the `external` network |
| Rate limiting | nginx enforces 60 requests/minute per IP on the `/api/` prefix |
| Docker socket | Only `update-manager` (profile: updater) and `watchtower` (profile: watchtower) mount the Docker socket — both are opt-in profiles |

When deploying in a shared or production environment:
- Rotate `ONEINFINITY_API_KEY` to a cryptographically random value (`python3 -c "import secrets; print(secrets.token_urlsafe(32))"`).
- Change `GRAFANA_PASSWORD` from the default `admin`.
- Do not expose Redis port (`REDIS_PORT`) to the public internet.
- Review and restrict `WORKER_CPU_LIMIT` and `WORKER_MEM_LIMIT` to match your host capacity.