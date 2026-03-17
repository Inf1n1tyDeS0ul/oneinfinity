"""Phase 1: Authorization enforcement before any active scanning."""

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from modules.utils import banner, section, ok, info, warn, err, ask, bold


@dataclass
class AuthRecord:
    authorized: bool
    auth_type: str
    auth_ref: str
    details: str = ""


class AuthEnforcer:
    def __init__(self, program_dir: str):
        self.program_dir = Path(program_dir)

    def verify(self, target: str, auth_type: str, auth_ref: str = "") -> AuthRecord:
        """Main entry — dispatch to correct auth flow. Aborts on failure."""
        banner("Phase 1 — Authorization Enforcement")
        info(f"Target  : {target}")
        info(f"Auth    : {auth_type}")

        # Always try scope.yaml shortcut first
        yaml_rec = self._check_scope_yaml()
        if yaml_rec and yaml_rec.authorized:
            ok("scope.yaml already marks this engagement as authorized.")
            return yaml_rec

        if auth_type == "bugbounty":
            rec = self._verify_bugbounty(target, auth_ref)
        elif auth_type == "contract":
            rec = self._verify_contract(target, auth_ref)
        elif auth_type == "owner":
            rec = self._verify_owner(target)
        elif auth_type == "scope_yaml":
            rec = yaml_rec or AuthRecord(False, "scope_yaml", "", "scope.yaml not found or not authorized")
        else:
            err(f"Unknown auth type: {auth_type}")
            sys.exit(1)

        if not rec.authorized:
            err("Authorization check FAILED.")
            err(rec.details)
            err("Aborting — scanning without authorization is illegal.")
            sys.exit(1)

        ok(f"Authorization confirmed ({rec.auth_type})")
        if rec.details:
            info(rec.details)
        return rec

    # ── Bug bounty ────────────────────────────────────────────────────────────

    def _verify_bugbounty(self, target: str, program_url: str) -> AuthRecord:
        if not program_url:
            err("--url <program-url> is required for --auth bugbounty")
            sys.exit(1)
        info(f"Fetching program page: {program_url}")
        try:
            import urllib.request
            req = urllib.request.Request(
                program_url,
                headers={"User-Agent": "Mozilla/5.0 (OneInfinity/1.0)"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8", errors="replace").lower()
        except Exception as e:
            warn(f"Could not fetch program page: {e}")
            return self._manual_confirmation(target, "bugbounty", program_url)

        # Extract root domain for matching
        root = self._root_domain(target)
        if root in content:
            return AuthRecord(
                authorized=True,
                auth_type="bugbounty",
                auth_ref=program_url,
                details=f"Domain '{root}' found in program page scope section.",
            )
        # Fallback: interactive confirmation
        warn(f"Could not automatically confirm '{root}' in program scope.")
        warn("You must manually confirm this target is in scope.")
        print()
        print(f"  Program URL : {program_url}")
        print(f"  Target      : {target}")
        print()
        ans = ask("Is this target explicitly listed in scope? (yes/no): ").strip().lower()
        if ans == "yes":
            return AuthRecord(True, "bugbounty", program_url,
                              "Manual confirmation by researcher.")
        return AuthRecord(False, "bugbounty", program_url,
                          "Target not confirmed as in-scope.")

    # ── Contract ──────────────────────────────────────────────────────────────

    def _verify_contract(self, target: str, contract_path: str) -> AuthRecord:
        if not contract_path:
            err("--contract <file> is required for --auth contract")
            sys.exit(1)
        p = Path(contract_path)
        if not p.exists():
            err(f"Contract file not found: {contract_path}")
            sys.exit(1)

        # Read text (txt / simple pdf text extraction)
        content = ""
        try:
            content = p.read_text(errors="replace").lower()
        except Exception as e:
            err(f"Cannot read contract: {e}")
            sys.exit(1)

        root = self._root_domain(target)
        if root not in content and target.lower() not in content:
            warn(f"Target '{target}' not found in contract text.")
            return AuthRecord(False, "contract", contract_path,
                              "Target not mentioned in contract document.")

        # Require explicit typed acknowledgment
        print()
        section("Contract Acknowledgment Required")
        print(f"  Contract  : {contract_path}")
        print(f"  Target    : {target}")
        print()
        print("  Type exactly:  I CONFIRM")
        ans = ask("Confirmation: ").strip()
        if ans == "I CONFIRM":
            return AuthRecord(True, "contract", contract_path,
                              f"Tester confirmed contract covers {target}.")
        return AuthRecord(False, "contract", contract_path,
                          "Tester did not confirm.")

    # ── Owner ─────────────────────────────────────────────────────────────────

    def _verify_owner(self, target: str) -> AuthRecord:
        banner("Owner Authorization")
        print("  This mode is for testing systems you own or have explicit")
        print("  written permission to test.")
        print()
        expected = f"I own {target} and authorize this test"
        print(f"  Type exactly:")
        print(f"  {bold(expected)}")
        print()
        ans = ask("Your statement: ").strip()
        if ans == expected:
            return AuthRecord(True, "owner", target,
                              "Owner typed acknowledgment.")
        warn("Statement did not match. Authorization denied.")
        return AuthRecord(False, "owner", target,
                          "Required statement not typed correctly.")

    # ── scope.yaml shortcut ───────────────────────────────────────────────────

    def _check_scope_yaml(self) -> "AuthRecord | None":
        scope_file = self.program_dir / "scope.yaml"
        if not scope_file.exists():
            return None
        try:
            from modules.scope import ScopeManager
            sm = ScopeManager(str(self.program_dir))
            sm.load()
            if sm.is_pentest():
                eng = sm._data.get("engagement", {})
                if eng.get("authorized"):
                    auth_doc = eng.get("auth_document", "scope.yaml")
                    return AuthRecord(True, "scope_yaml", str(scope_file),
                                      f"Pentest engagement authorized. Doc: {auth_doc}")
                return AuthRecord(False, "scope_yaml", str(scope_file),
                                  "scope.yaml: authorized is false.")
            else:
                prog = sm._data.get("program", {})
                if prog.get("registered"):
                    return AuthRecord(True, "scope_yaml", str(scope_file),
                                      f"Bug bounty program registered: {prog.get('name', '')}")
                return AuthRecord(False, "scope_yaml", str(scope_file),
                                  "scope.yaml: registered is false.")
        except Exception:
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _root_domain(target: str) -> str:
        """Extract root domain (last two labels)."""
        host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    def _manual_confirmation(self, target: str, auth_type: str, ref: str) -> AuthRecord:
        warn("Manual authorization confirmation required.")
        ans = ask(f"Do you have written authorization to test {target}? (yes/no): ").strip().lower()
        if ans == "yes":
            return AuthRecord(True, auth_type, ref, "Manual confirmation.")
        return AuthRecord(False, auth_type, ref, "User denied authorization.")
