#!/usr/bin/env python3
"""
OneInfinity Unified Scanner - CLI Interface
============================================
Single scanner orchestrating 17-phase autonomous pentest pipeline:
- External CLI tools (nuclei, sqlmap, dalfox, etc.)
- 32 pure-Python security scanners
- Attack chain detection with auto-PoC generation
- AI-powered exploit correlation

Usage:
    python cli_scan.py <target> [--config config.json]

Examples:
    # Basic scan
    python cli_scan.py https://example.com

    # Authenticated scan
    python cli_scan.py https://example.com --config '{"cookies": {"session": "abc123"}}'

    # Custom scan config file
    python cli_scan.py https://example.com --config auth_config.json
"""
import argparse
import json
import signal
import sys
import uuid
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from oneinfinity.scan.unified_scan_engine import get_engine


def progress_callback(phase: str, pct: int, msg: str) -> None:
    """Pretty progress display"""
    bar_len = 40
    filled = int(bar_len * pct / 100)
    bar = '█' * filled + '░' * (bar_len - filled)
    print(f"\r[{bar}] {pct:3d}% | {phase:20s} | {msg[:50]}", end='', flush=True)


def main():
    # Global state for signal handler
    active_scan_id = None
    scan_interrupted = False

    def signal_handler(signum, frame):
        """Graceful shutdown on Ctrl+C - saves partial results."""
        nonlocal scan_interrupted
        if scan_interrupted:
            # Second interrupt - force exit
            print("\n[!] Force quit (findings may be lost)")
            sys.exit(130)

        scan_interrupted = True
        if active_scan_id:
            print(f"\n[*] Interrupt received - stopping scan {active_scan_id} gracefully...")
            print("[*] Collected findings will be saved to database")
            try:
                get_engine().stop(active_scan_id)
            except Exception:
                pass  # Scanner may already be stopping
        sys.exit(130)

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(
        description="OneInfinity Unified Scanner - Complete security assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --config '{"cookies": {"session": "abc"}}'
  %(prog)s https://api.example.com --config auth.json
        """
    )
    parser.add_argument('target', help='Target URL or domain to scan')
    parser.add_argument(
        '--config',
        help='Scan config as JSON string or path to JSON file',
        default=None
    )
    parser.add_argument(
        '--output',
        help='Output directory for reports (default: auto-generated)',
        default=None
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress progress output'
    )
    parser.add_argument(
        '--scanner',
        choices=['deser', 'http2', 'prototype-pollution', 'supply-chain', 'model-extraction'],
        action='append',
        dest='scanners',
        metavar='SCANNER',
        help=(
            'Tag a specific scanner for reporting focus (repeatable). '
            'Choices: deser, http2, prototype-pollution, supply-chain, model-extraction. '
            'All run unconditionally in the full pipeline; this flag '
            'is informational and recorded in scan_config for filtering.'
        )
    )
    parser.add_argument(
        '--stealth-trace',
        action='store_true',
        dest='stealth_trace',
        help='Enable eBPF/Frida stealth tracer for syscall and function-level monitoring'
    )
    parser.add_argument(
        '--fuzzer-strategy',
        choices=['structured', 'json_path', 'websocket', 'havoc'],
        dest='fuzzer_strategy',
        default=None,
        help='LibAFL/Rust fuzzer mutation strategy'
    )
    parser.add_argument(
        '--corpus-dir',
        dest='corpus_dir',
        metavar='PATH',
        default=None,
        help='Directory containing seed corpus for the fuzzer'
    )
    parser.add_argument(
        '--ai-campaign',
        choices=['agentic_injection', 'model_extraction'],
        dest='ai_campaign',
        default=None,
        help='AI red team campaign type to run alongside the scan'
    )
    parser.add_argument(
        '--god-mode',
        action='store_true',
        dest='god_mode',
        help='Run full god mode deep scan (all capabilities, all missions, maximum coverage)'
    )
    parser.add_argument(
        '--scan-type',
        choices=['quick', 'full', 'api', 'mobile', 'web3', 'ai', 'god_mode'],
        dest='scan_type',
        default='full',
        help='Scan profile type (default: full)'
    )
    parser.add_argument(
        '--race-condition',
        action='store_true',
        dest='race_condition',
        help='Enable race condition testing on payment/coupon/upload endpoints'
    )
    parser.add_argument(
        '--websocket',
        action='store_true',
        dest='websocket',
        help='Enable WebSocket attack testing'
    )
    args = parser.parse_args()

    # Parse scan config
    scan_config = {}
    if args.config:
        config_path = Path(args.config)
        if config_path.exists():
            scan_config = json.loads(config_path.read_text())
            print(f"[*] Loaded config from {config_path}")
        else:
            try:
                scan_config = json.loads(args.config)
                print("[*] Loaded config from command line")
            except json.JSONDecodeError:
                print(f"[!] Invalid JSON config: {args.config}", file=sys.stderr)
                return 1

    # Merge new Phase 2 flags into scan_config
    if args.scanners:
        scan_config.setdefault('advanced_scanners', [])
        for s in args.scanners:
            if s not in scan_config['advanced_scanners']:
                scan_config['advanced_scanners'].append(s)
    if args.stealth_trace:
        scan_config['stealth_trace'] = True
    if args.fuzzer_strategy:
        scan_config['fuzzer_strategy'] = args.fuzzer_strategy
    if args.corpus_dir:
        corpus = Path(args.corpus_dir)
        if not corpus.is_dir():
            print(f"[!] --corpus-dir does not exist: {args.corpus_dir}", file=sys.stderr)
            return 1
        scan_config['corpus_dir'] = str(corpus.resolve())
    if args.ai_campaign:
        scan_config['ai_campaign'] = args.ai_campaign
    if args.god_mode or args.scan_type == 'god_mode':
        scan_config['scan_type'] = 'god_mode'
    elif args.scan_type and args.scan_type != 'full':
        scan_config['scan_type'] = args.scan_type
    if args.race_condition:
        scan_config['enable_race_condition'] = True
    if args.websocket:
        scan_config['enable_websocket'] = True

    # Run scan
    print(f"\n[*] Starting unified scan on {args.target}")
    print(f"[*] Phases: 17 sequential (classify → recon → scan → validate → chain → report)")
    print(f"[*] Scanners: External tools + 32 Python modules")
    print(f"[*] Press Ctrl+C to stop gracefully (findings will be saved)")
    print()
    if scan_config.get('advanced_scanners'):
        print(f"[*] Advanced scanners: {', '.join(scan_config['advanced_scanners'])}")
    if scan_config.get('stealth_trace'):
        print("[*] Stealth trace: eBPF/Frida enabled")
    if scan_config.get('fuzzer_strategy'):
        print(f"[*] Fuzzer strategy: {scan_config['fuzzer_strategy']}")
    if scan_config.get('corpus_dir'):
        print(f"[*] Corpus dir: {scan_config['corpus_dir']}")
    if scan_config.get('ai_campaign'):
        print(f"[*] AI campaign: {scan_config['ai_campaign']}")

    cb = None if args.quiet else progress_callback

    try:
        engine = get_engine()
        # Start async to get session ID immediately
        session = engine.scan_async(
            target=args.target,
            scan_config=scan_config or {},
            on_progress=cb,
        )
        active_scan_id = session.scan_id
        
        # Wait for completion
        while session.status == "running":
            time.sleep(1)
            
    except KeyboardInterrupt:
        # Handled by signal handler, but just in case
        print("\n\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n\n[!] Scan failed: {e}", file=sys.stderr)
        return 1
    finally:
        active_scan_id = None

    # Print results
    if not args.quiet:
        print("\n\n")

    print(f"[*] Scan complete: {session.scan_id}")
    print(f"[*] Status: {session.status}")
    print(f"[*] Findings: {len(session.findings)}")
    
    if session.findings:
        print("\n[+] Top Findings:")
        # Sort by severity
        sev_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(session.findings, key=lambda x: sev_map.get(x.get('severity', 'info').lower(), 5))
        for f in sorted_findings[:10]:
            print(f"  - [{f.get('severity', '???').upper()}] {f.get('title') or f.get('vuln_type')}")
            if f.get('url'):
                print(f"    URL: {f.get('url')}")
    
    if session.error:
        print(f"\n[!] Errors encountered: {session.error}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
