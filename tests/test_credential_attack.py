"""tests/test_credential_attack.py — Unit tests for credential attack pipeline."""
from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock


# ── CredentialSprayEngine ────────────────────────────────────────────────────


def test_spray_engine_imports():
    from oneinfinity.attack.credential.spray_engine import CredentialSprayEngine
    assert CredentialSprayEngine is not None


def test_spray_dry_run_does_not_make_requests():
    """dry_run=True should log attempts without sending actual HTTP requests."""
    from oneinfinity.attack.credential.spray_engine import CredentialSprayEngine

    engine = CredentialSprayEngine(
        target_url="https://example.com/login",
        dry_run=True,
    )
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200)
        report = engine.spray(
            usernames=["admin"],
            passwords=["password123"],
            with_credential_attack=True,
        )
    mock_post.assert_not_called()
    assert report is not None


def test_spray_requires_with_credential_attack_flag():
    """Live spray without with_credential_attack=True should raise RuntimeError."""
    from oneinfinity.attack.credential.spray_engine import CredentialSprayEngine

    engine = CredentialSprayEngine(
        target_url="https://example.com/login",
        dry_run=False,
    )
    with pytest.raises(RuntimeError, match="with-credential-attack"):
        engine.spray(["admin"], ["pw"], with_credential_attack=False)


def test_spray_dry_run_returns_report():
    from oneinfinity.attack.credential.spray_engine import CredentialSprayEngine, SprayReport

    engine = CredentialSprayEngine(target_url="https://example.com/login", dry_run=True)
    report = engine.spray(
        usernames=["user1", "user2"],
        passwords=["pw1", "pw2"],
        with_credential_attack=True,
    )
    assert isinstance(report, SprayReport)
    assert report.total_attempts == 4  # 2 users × 2 passwords


def test_spray_stop_on_success_dry_run():
    """stop_on_success=True in dry_run should not crash."""
    from oneinfinity.attack.credential.spray_engine import CredentialSprayEngine

    engine = CredentialSprayEngine(target_url="https://example.com/login", dry_run=True)
    report = engine.spray(
        usernames=["a", "b", "c"],
        passwords=["x"],
        stop_on_success=True,
        with_credential_attack=True,
    )
    assert report is not None


# ── WordlistGenerator ────────────────────────────────────────────────────────


def test_wordlist_generator_imports():
    from oneinfinity.attack.credential.spray_engine import WordlistGenerator
    g = WordlistGenerator()
    assert g is not None


def test_from_domain_returns_list():
    from oneinfinity.attack.credential.spray_engine import WordlistGenerator
    g = WordlistGenerator()
    with patch.object(g, "_fetch", return_value="<p>Acme Corp welcome page</p>"):
        words = g.from_domain("acme.com")
    assert isinstance(words, list)
    assert len(words) > 0
    assert any("acme" in w.lower() for w in words)


def test_mutate_generates_variants():
    from oneinfinity.attack.credential.spray_engine import WordlistGenerator
    g = WordlistGenerator()
    variants = g._mutate("acme")
    assert len(variants) > 1
    assert any("2024" in v or "!" in v or "@" in v for v in variants)


# ── EmployeeOSINT ────────────────────────────────────────────────────────────


def test_employee_osint_imports():
    from oneinfinity.attack.credential.spray_engine import EmployeeOSINT
    o = EmployeeOSINT()
    assert o is not None


def test_from_names_generates_usernames():
    from oneinfinity.attack.credential.spray_engine import EmployeeOSINT
    o = EmployeeOSINT()
    usernames = o.from_names(["John Doe", "Jane Smith"])
    assert len(usernames) >= 4
    assert any("john" in u.lower() for u in usernames)


def test_from_github_org_without_token():
    """from_github_org() without a token returns a list (may be empty on rate limit)."""
    from oneinfinity.attack.credential.spray_engine import EmployeeOSINT
    o = EmployeeOSINT()
    with patch("urllib.request.urlopen", side_effect=Exception("rate limited")):
        result = o.from_github_org("google")
    assert isinstance(result, list)


# ── HIBPChecker ──────────────────────────────────────────────────────────────


def test_hibp_checker_imports():
    from oneinfinity.attack.credential.spray_engine import HIBPChecker
    c = HIBPChecker()
    assert c is not None


def test_is_pwned_with_mock():
    import hashlib
    from oneinfinity.attack.credential.spray_engine import HIBPChecker

    pw = "password123"
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    suffix = sha1[5:]

    mock_resp = MagicMock()
    mock_resp.read.return_value = f"{suffix}:9876543\r\nABCDE:1\r\n".encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        checker = HIBPChecker()
        found, count = checker.is_pwned(pw)
    assert found is True
    assert count == 9876543


def test_filter_pwned_returns_known_breached():
    import hashlib
    from oneinfinity.attack.credential.spray_engine import HIBPChecker

    pw = "qwerty"
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    suffix = sha1[5:]

    mock_resp = MagicMock()
    mock_resp.read.return_value = f"{suffix}:12345\r\n".encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        checker = HIBPChecker()
        pwned = checker.filter_pwned(["qwerty"])
    assert "qwerty" in pwned


# ── __init__ exports ─────────────────────────────────────────────────────────


def test_credential_package_exports():
    from oneinfinity.attack.credential import (
        CredentialSprayEngine, SprayReport, SprayAttempt,
        WordlistGenerator, EmployeeOSINT, HIBPChecker,
    )
    assert all([CredentialSprayEngine, SprayReport, SprayAttempt,
                WordlistGenerator, EmployeeOSINT, HIBPChecker])
