# tests/test_secrets_config.py
import pathlib

ROOT = pathlib.Path("/home/devendra-yadav/oneinfinity")

def test_no_changeme_in_compose():
    """Neither compose file should have changeme as a default value."""
    for fname in ["docker-compose.yml", "docker-compose.distributed.yml"]:
        path = ROOT / fname
        if not path.exists():
            continue
        content = path.read_text()
        assert "changeme" not in content, \
            f"{fname} still contains 'changeme' default key — must be removed"

def test_no_admin_grafana_password():
    """env.example must not ship with GRAFANA_PASSWORD=admin."""
    env_example = ROOT / ".env.example"
    if not env_example.exists():
        return  # file may not exist — ok
    content = env_example.read_text()
    assert "GRAFANA_PASSWORD=admin" not in content, \
        ".env.example ships GRAFANA_PASSWORD=admin — insecure default"

def test_api_key_env_var_documented():
    """.env.example should document ONEINFINITY_API_KEY."""
    env_example = ROOT / ".env.example"
    if not env_example.exists():
        return
    content = env_example.read_text()
    assert "ONEINFINITY_API_KEY" in content, \
        ".env.example should document ONEINFINITY_API_KEY"
