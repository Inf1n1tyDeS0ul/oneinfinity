"""
Environment Variable Manager
Centralized API key/token storage in .env file
"""

import os
from pathlib import Path
from typing import Dict, Optional, List


class EnvManager:
    """
    Manages .env file for API keys and tokens.
    Thread-safe singleton for centralized configuration.
    """

    _instance = None
    _env_file = None

    @classmethod
    def get_instance(cls, env_file: Optional[str] = None):
        if cls._instance is None:
            cls._instance = cls(env_file)
        return cls._instance

    def __init__(self, env_file: Optional[str] = None):
        if env_file:
            self._env_file = Path(env_file)
        else:
            # Default to project root .env
            self._env_file = Path.cwd() / ".env"

        # Create if doesn't exist
        if not self._env_file.exists():
            self._env_file.touch()

    def _read_env(self) -> Dict[str, str]:
        """Read all variables from .env file."""
        env_vars = {}
        if self._env_file.exists():
            with open(self._env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        # Remove quotes if present
                        value = value.strip().strip('"').strip("'")
                        env_vars[key.strip()] = value
        return env_vars

    def _write_env(self, env_vars: Dict[str, str]):
        """Write variables to .env file."""
        lines = []
        for key, value in sorted(env_vars.items()):
            # Quote values with special chars
            if ' ' in value or any(c in value for c in ['"', "'", '$', '`']):
                value = f'"{value}"'
            lines.append(f"{key}={value}")

        with open(self._env_file, 'w') as f:
            f.write('\n'.join(lines) + '\n')

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get single environment variable."""
        # Check OS env first (takes precedence)
        if key in os.environ:
            return os.environ[key]

        # Check .env file
        env_vars = self._read_env()
        return env_vars.get(key, default)

    def set(self, key: str, value: str):
        """Set single environment variable."""
        env_vars = self._read_env()
        env_vars[key] = value
        self._write_env(env_vars)

        # Update OS env
        os.environ[key] = value

    def set_multiple(self, updates: Dict[str, str]):
        """Set multiple environment variables."""
        env_vars = self._read_env()
        env_vars.update(updates)
        self._write_env(env_vars)

        # Update OS env
        for key, value in updates.items():
            os.environ[key] = value

    def delete(self, key: str):
        """Delete environment variable."""
        env_vars = self._read_env()
        if key in env_vars:
            del env_vars[key]
            self._write_env(env_vars)

        # Remove from OS env
        if key in os.environ:
            del os.environ[key]

    def get_all(self, prefix: Optional[str] = None) -> Dict[str, str]:
        """Get all environment variables, optionally filtered by prefix."""
        env_vars = self._read_env()

        if prefix:
            return {k: v for k, v in env_vars.items() if k.startswith(prefix)}

        return env_vars

    def get_github_tokens(self) -> List[str]:
        """Get all GitHub tokens (both single and comma-separated pool)."""
        tokens = []

        # Single token
        single = self.get("GITHUB_TOKEN")
        if single:
            tokens.append(single)

        # Token pool (comma-separated)
        pool = self.get("GITHUB_TOKENS")
        if pool:
            pool_tokens = [t.strip() for t in pool.split(",") if t.strip()]
            tokens.extend(pool_tokens)

        # Deduplicate
        return list(dict.fromkeys(tokens))

    def set_github_tokens(self, tokens: List[str]):
        """Set GitHub tokens (stores as comma-separated GITHUB_TOKENS)."""
        if not tokens:
            self.delete("GITHUB_TOKENS")
            return

        # Clean and deduplicate
        clean_tokens = [t.strip() for t in tokens if t.strip()]
        clean_tokens = list(dict.fromkeys(clean_tokens))

        # Store as comma-separated
        self.set("GITHUB_TOKENS", ",".join(clean_tokens))

    def get_api_keys(self) -> Dict[str, str]:
        """Get common API keys."""
        keys = [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GITHUB_TOKEN",
            "GITHUB_TOKENS",
            "SHODAN_API_KEY",
            "VIRUSTOTAL_API_KEY",
            "CENSYS_API_ID",
            "CENSYS_API_SECRET",
            "SECURITYTRAILS_API_KEY",
            "URLSCAN_API_KEY",
            "HUNTER_API_KEY",
        ]

        result = {}
        for key in keys:
            value = self.get(key)
            if value:
                result[key] = value

        return result

    def validate_github_token(self, token: str) -> bool:
        """Validate GitHub token format."""
        if not token or len(token) < 20:
            return False

        # GitHub token prefixes
        valid_prefixes = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]
        return any(token.startswith(prefix) for prefix in valid_prefixes)


# Singleton instance
env_manager = EnvManager.get_instance()
