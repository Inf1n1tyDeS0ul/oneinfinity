"""
council — Autonomous Vulnerability Discovery Council commands.

Subcommands:
  council run    --target TEXT [--scan-id TEXT] [--max-rounds INT]
  council status --scan-id TEXT
"""
from __future__ import annotations

import json
import time
import uuid
import logging
from pathlib import Path

log = logging.getLogger(__name__)

__all__ = ["cmd_council"]


# ── minimal stub foundation ────────────────────────────────────────────────────

class _StubFoundation:
    """Minimal Foundation-duck-type for standalone CLI mode (no live Foundation)."""
    recon: object = None
    app_model: object = None
    auth_context: object = None


# ── council run ───────────────────────────────────────────────────────────────

def _run_council(args) -> None:
    """council run --target URL [--scan-id ID] [--max-rounds N]"""
    target: str = getattr(args, "target", "") or ""
    if not target:
        print("  [!] --target is required for `council run`")
        return

    raw_scan_id: str = getattr(args, "scan_id", "") or ""
    scan_id: str = raw_scan_id.strip() or str(uuid.uuid4())
    max_rounds: int = int(getattr(args, "max_rounds", 3) or 3)

    print(f"\n  [*] Council scan starting")
    print(f"      scan-id : {scan_id}")
    print(f"      target  : {target}")
    print(f"      rounds  : {max_rounds}")
    print()

    # ── import council mission ─────────────────────────────────────────────
    try:
        from oneinfinity.orchestration.god_mode_engine import AICouncilMission
    except ImportError as exc:
        print(f"  [!] AICouncilMission unavailable: {exc}")
        print("      Run `oneinfinity doctor` to check dependencies.")
        return

    from oneinfinity.orchestration.god_mode_engine import GodModeSession

    session = GodModeSession(
        scan_id=scan_id,
        target=target,
        start_time=time.time(),
        max_findings=0,
        max_time=0,
    )

    foundation = _StubFoundation()
    mission = AICouncilMission(foundation=foundation, auth_config={})
    if max_rounds:
        try:
            mission.max_rounds = max_rounds  # type: ignore[attr-defined]
        except AttributeError:
            pass

    try:
        mission.run_sync(session)
    except Exception as exc:
        print(f"  [!] Council mission error: {exc}")
        log.debug("council run error", exc_info=True)
        return

    # ── print summary ─────────────────────────────────────────────────────
    print("\n  [+] Council run complete")
    print(f"      elapsed   : {session.elapsed():.1f}s")
    print(f"      findings  : {session.finding_count}")

    # surface_profile
    try:
        surface_profile = getattr(mission, "surface_profile", None)
        if surface_profile is not None:
            output_type = getattr(surface_profile, "output_type", "unknown")
            model_hint  = getattr(surface_profile, "model_hint", "")
            print(f"      surface   : output_type={output_type}"
                  + (f", model_hint={model_hint}" if model_hint else ""))
    except Exception:
        pass

    # exploit plan
    try:
        exploit_plan = getattr(mission, "exploit_plan", None)
        if exploit_plan is not None:
            steps = getattr(exploit_plan, "steps", None) or []
            print(f"      plan steps: {len(steps)}")
    except Exception:
        pass

    # exploit trace
    try:
        exploit_trace = getattr(mission, "exploit_trace", None)
        if exploit_trace is not None:
            success_count = getattr(exploit_trace, "success_count", None)
            if success_count is not None:
                print(f"      successes : {success_count}")
    except Exception:
        pass

    print()


# ── council status ────────────────────────────────────────────────────────────

def _status_council(args) -> None:
    """council status --scan-id ID"""
    scan_id: str = getattr(args, "scan_id", "") or ""
    if not scan_id:
        print("  [!] --scan-id is required for `council status`")
        return

    # ── Try local filesystem first ─────────────────────────────────────────
    home_dir = Path.home() / ".oneinfinity" / scan_id / "sensor"
    profile_path = home_dir / "profile.json"
    if profile_path.exists():
        try:
            data = json.loads(profile_path.read_text())
            print(f"\n  Council scan status — {scan_id}")
            print(f"  output_type      : {data.get('output_type', 'unknown')}")
            print(f"  profile_complete : {data.get('profile_complete', False)}")
            print(f"  model_hint       : {data.get('model_hint', '')}")
            blocked = data.get("blocked_keywords", [])
            print(f"  blocked_keywords : {len(blocked)} entries")
            tools = data.get("tool_list", [])
            if tools:
                print(f"  tools            : {', '.join(tools[:5])}"
                      + (" …" if len(tools) > 5 else ""))
            print()
            return
        except Exception as exc:
            log.debug("profile.json read error: %s", exc)

    # ── Fallback: DB query ─────────────────────────────────────────────────
    try:
        import asyncio as _asyncio
        from oneinfinity.core.pg_client import get_council_run as _get_run

        row = _asyncio.run(_get_run(scan_id))
        if row:
            print(f"\n  Council run — {scan_id}")
            for k, v in row.items():
                print(f"  {k:<22}: {v}")
            print()
            return
    except Exception as exc:
        log.debug("DB council_run lookup failed: %s", exc)

    print(f"  [!] No council run data found for scan-id: {scan_id}")
    print(f"      Expected profile at: {profile_path}")


# ── dispatcher ────────────────────────────────────────────────────────────────

def cmd_council(args) -> None:
    """Dispatch council sub-subcommand (run / status)."""
    subcommand: str = getattr(args, "council_subcommand", None) or ""

    if subcommand == "run":
        _run_council(args)
    elif subcommand == "status":
        _status_council(args)
    else:
        # No subcommand — show council help.
        print("Usage: oneinfinity council <subcommand> [options]")
        print()
        print("Subcommands:")
        print("  run     --target URL [--scan-id ID] [--max-rounds N]")
        print("  status  --scan-id ID")
        print()
        print("Run `oneinfinity council run --help` for full options.")
