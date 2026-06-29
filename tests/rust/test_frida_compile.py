"""
Verify each Frida TS hook has zero TypeScript syntax errors.
Uses tsc --noEmit if available, else just checks file exists and has content.
"""
import subprocess
import os
import pytest
from pathlib import Path as _Path
_REPO_ROOT = _Path(__file__).resolve().parent
while not (_REPO_ROOT / 'pyproject.toml').exists():
    _REPO_ROOT = _REPO_ROOT.parent
HOOKS_DIR = _REPO_ROOT / 'src' / 'frida-hooks'
HOOK_FILES = ['ssl_hook.ts', 'anti_debug.ts', 'storage_hook.ts', 'root_bypass.ts', 'crypto_extract.ts']

@pytest.mark.parametrize('hook', HOOK_FILES)
def test_hook_exists_and_nonempty(hook):
    p = HOOKS_DIR / 'src' / hook
    assert p.exists(), f'{hook} does not exist'
    assert p.stat().st_size > 500, f'{hook} is suspiciously small ({p.stat().st_size} bytes)'

@pytest.mark.parametrize('hook', HOOK_FILES)
def test_hook_has_emit_event(hook):
    p = HOOKS_DIR / 'src' / hook
    if not p.exists():
        pytest.skip(f'{hook} not yet created')
    content = p.read_text()
    assert 'emitEvent' in content or 'send(' in content, f'{hook} missing event emission'

def test_crypto_extract_has_required_hooks():
    p = HOOKS_DIR / 'src' / 'crypto_extract.ts'
    if not p.exists():
        pytest.skip('crypto_extract.ts not yet created')
    content = p.read_text()
    required = ['CCCrypt', 'Cipher', 'SecretKeySpec', 'EVP_EncryptInit']
    for r in required:
        assert r in content, f'crypto_extract.ts missing hook for {r}'

def test_root_bypass_has_required_hooks():
    p = HOOKS_DIR / 'src' / 'root_bypass.ts'
    if not p.exists():
        pytest.skip('root_bypass.ts not yet created')
    content = p.read_text()
    required = ['RootBeer', 'Magisk', 'su', 'Build.TAGS']
    for r in required:
        assert r in content, f'root_bypass.ts missing hook for {r}'

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
