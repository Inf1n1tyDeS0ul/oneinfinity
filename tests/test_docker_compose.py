# tests/test_docker_compose.py
import pathlib

ROOT = pathlib.Path("/home/devendra-yadav/oneinfinity")


def _load_compose(filename):
    import yaml
    with open(ROOT / filename) as f:
        return yaml.safe_load(f)


def test_frontend_volume_not_readonly():
    """Frontend volume must NOT be read-only — npm ci needs write access."""
    cfg = _load_compose("docker-compose.yml")
    frontend = cfg["services"]["frontend"]
    volumes = frontend.get("volumes", [])
    for vol in volumes:
        vol_str = str(vol)
        assert ":ro" not in vol_str, (
            f"Frontend volume is read-only — npm ci cannot write node_modules: {vol_str}\n"
            "Fix: remove ':ro' from the frontend volume mount"
        )


def test_backend_not_in_reload_mode():
    """Backend command must not use --reload (dev-only flag)."""
    cfg = _load_compose("docker-compose.yml")
    backend_cmd = str(cfg["services"]["backend"].get("command", ""))
    assert "--reload" not in backend_cmd, (
        f"Backend uses --reload which is dev-only. Remove it for production.\n"
        f"Current command: {backend_cmd}"
    )


def test_vite_proxy_uses_env_variable():
    """Vite proxy must not be hardcoded to localhost:8000."""
    vite_cfg = (ROOT / "web/frontend/vite.config.js").read_text()
    # Must NOT have the hardcoded value without env var fallback
    import re
    # Check if there's a hardcoded localhost:8000 without any env var around it
    has_env = "process.env" in vite_cfg or "VITE_BACKEND_URL" in vite_cfg
    hardcoded_only = "localhost:8000" in vite_cfg and not has_env
    assert not hardcoded_only, (
        "Vite proxy is hardcoded to localhost:8000 with no env override.\n"
        "In Docker, the backend is at http://backend:8000, not localhost.\n"
        "Fix: use process.env.VITE_BACKEND_URL || 'http://localhost:8000'"
    )


def test_compose_files_parse_as_valid_yaml():
    """Both compose files must be valid YAML."""
    for fname in ["docker-compose.yml", "docker-compose.distributed.yml"]:
        path = ROOT / fname
        if not path.exists():
            continue
        import yaml
        try:
            yaml.safe_load(path.read_text())
        except yaml.YAMLError as e:
            assert False, f"{fname} is not valid YAML: {e}"


def test_redis_service_exists_in_compose():
    """Redis service must exist in docker-compose.yml for worker to function."""
    cfg = _load_compose("docker-compose.yml")
    services = cfg.get("services", {})
    assert "redis" in services, (
        "No 'redis' service in docker-compose.yml. "
        "The distributed worker requires Redis (BLPOP) — without it the worker cannot start. "
        "Add a Redis service under the 'full' or 'distributed' profile."
    )


def test_redis_has_healthcheck():
    """Redis service should have a healthcheck."""
    cfg = _load_compose("docker-compose.yml")
    services = cfg.get("services", {})
    if "redis" not in services:
        return  # other test will catch this
    redis_svc = services["redis"]
    assert "healthcheck" in redis_svc, "Redis service should have a healthcheck"


def test_dockerfile_uses_python_313():
    """Dockerfile must use Python 3.13 to match the host environment."""
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "python:3.11" not in dockerfile, (
        "Dockerfile uses python:3.11 but host runs 3.13. "
        "Update all FROM python:3.11 lines to python:3.13"
    )
    # Dockerfile may use ARG PYTHON_VERSION=3.13 with FROM python:${PYTHON_VERSION}-...
    # Accept either the literal string or the ARG-based pattern
    has_explicit = "python:3.13" in dockerfile
    has_arg_based = "PYTHON_VERSION=3.13" in dockerfile
    assert has_explicit or has_arg_based, (
        "Dockerfile should explicitly use python:3.13 (either directly or via ARG PYTHON_VERSION=3.13)"
    )
