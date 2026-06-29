"""setup_env.py — Automated environment setup for new OneInfinity installs."""
import subprocess
import sys
import os
from pathlib import Path
from oneinfinity.core.environment import check_environment, IS_MACOS, IS_LINUX
from oneinfinity.core.path_resolver import get_oneinfinity_home


def setup():
    print('OneInfinity Environment Setup')
    print('=' * 50)

    # 1. Create data directory
    home = get_oneinfinity_home()
    for d in ['wordlists', 'reports', 'raw', 'databases', 'logs']:
        (home / d).mkdir(parents=True, exist_ok=True)
    print(f'\u2705 Data directory: {home}')

    # 2. Check tools
    print('\nChecking tools...')
    statuses = check_environment(verbose=True)
    missing = [s for s in statuses.values() if not s.available]

    if missing:
        print(f'\n\u26a0\ufe0f  {len(missing)} tools missing. Install with:')
        for s in missing[:10]:
            print(f'  {s.install_hint}')
    else:
        print('\u2705 All tools available')

    # 3. Create .env if missing
    env_path = Path.cwd() / '.env'
    env_example = Path.cwd() / '.env.example'
    if not env_path.exists() and env_example.exists():
        import shutil
        shutil.copy(env_example, env_path)
        print(f'\u2705 Created .env from .env.example')

    print('\nSetup complete. Run: oneinfinity scan <target>')


if __name__ == '__main__':
    setup()
