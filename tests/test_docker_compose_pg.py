# tests/test_docker_compose_pg.py
import pathlib, yaml

COMPOSE = yaml.safe_load(
    pathlib.Path("/home/devendra-yadav/oneinfinity/docker-compose.yml").read_text()
)
SERVICES = COMPOSE.get("services", {})

def test_postgres_service_exists():
    assert "postgres" in SERVICES

def test_postgres_uses_16_alpine():
    assert "16" in SERVICES["postgres"].get("image", "")

def test_postgres_has_data_volume():
    vols = str(SERVICES["postgres"].get("volumes", []))
    assert "pg_data" in vols or "postgres" in vols

def test_redis_exposed_to_host():
    """Redis must publish port 6379 for CLI access."""
    ports = str(SERVICES.get("redis", {}).get("ports", []))
    assert "6379" in ports

def test_backend_has_postgres_url():
    env = SERVICES.get("backend", {}).get("environment", [])
    env_str = str(env)
    assert "POSTGRES_URL" in env_str

def test_postgres_volume_in_top_level():
    volumes = COMPOSE.get("volumes", {})
    assert any("pg" in k or "postgres" in k for k in volumes)
