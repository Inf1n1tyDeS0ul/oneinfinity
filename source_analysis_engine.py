"""
Source Analysis Engine — Multi-language static analysis for security vulnerabilities
"""
import re
import ast
import json
import os
import logging
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CodeFinding:
    file_path: str
    line_number: int
    vuln_type: str
    severity: str          # critical / high / medium / low / info
    title: str
    code_snippet: str
    description: str
    cwe_id: Optional[str] = None

    def to_dict(self):
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "title": self.title,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "cwe_id": self.cwe_id,
        }


@dataclass
class RouteInfo:
    path: str
    method: str
    handler: str
    file_path: str
    line_number: int
    auth_required: bool = False
    params: list = field(default_factory=list)

    def to_dict(self):
        return {
            "path": self.path,
            "method": self.method,
            "handler": self.handler,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "auth_required": self.auth_required,
            "params": self.params,
        }


@dataclass
class DataFlow:
    source: str           # user input location
    sink: str             # dangerous function
    passes_through: list = field(default_factory=list)
    sanitized: bool = False

    def to_dict(self):
        return {
            "source": self.source,
            "sink": self.sink,
            "passes_through": self.passes_through,
            "sanitized": self.sanitized,
        }


@dataclass
class SourceAnalysisResult:
    target_path: str
    language_stats: dict = field(default_factory=dict)
    routes: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    data_flows: list = field(default_factory=list)

    def to_dict(self):
        return {
            "target_path": self.target_path,
            "language_stats": self.language_stats,
            "routes": [r.to_dict() if hasattr(r, "to_dict") else r for r in self.routes],
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings],
            "data_flows": [d.to_dict() if hasattr(d, "to_dict") else d for d in self.data_flows],
        }


# ---------------------------------------------------------------------------
# Vulnerability pattern dictionaries
# ---------------------------------------------------------------------------

# (regex, severity, vuln_type, description, cwe_id)
PYTHON_VULN_PATTERNS = {
    "sql_injection": (
        r'execute\s*\(\s*["\'].*%[sd].*["\']|execute\s*\(\s*f["\']',
        "critical",
        "SQL Injection",
        "String formatting used inside SQL execute() — attacker-controlled input can manipulate the query.",
        "CWE-89",
    ),
    "command_injection": (
        r'os\.system\s*\(|subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True',
        "critical",
        "Command Injection",
        "Shell=True or os.system() with potential user-controlled input enables arbitrary OS command execution.",
        "CWE-78",
    ),
    "insecure_deserialization": (
        r'pickle\.loads?\s*\(',
        "high",
        "Insecure Deserialization",
        "pickle.load/loads() on untrusted data can lead to arbitrary code execution.",
        "CWE-502",
    ),
    "hardcoded_secret": (
        r'(?i)(password|secret|key|token)\s*=\s*["\'][^"\']{8,}["\']',
        "high",
        "Hardcoded Secret",
        "Sensitive credential or secret appears hardcoded in source — should be loaded from environment or secrets manager.",
        "CWE-798",
    ),
    "eval_injection": (
        r'\beval\s*\(',
        "critical",
        "Eval Injection",
        "eval() with user-controlled input allows arbitrary code execution.",
        "CWE-95",
    ),
    "path_traversal": (
        r'open\s*\(.*\+|open\s*\(.*request\.',
        "high",
        "Path Traversal",
        "File open with user-supplied path component may allow directory traversal.",
        "CWE-22",
    ),
    "ssrf": (
        r'requests\.(get|post)\s*\(.*request\.',
        "high",
        "SSRF",
        "HTTP request made with URL derived from request data — may enable SSRF.",
        "CWE-918",
    ),
    "xxe": (
        r'(?:xml\.etree|lxml\.etree)',
        "medium",
        "XXE",
        "XML parsing without defusedxml may be vulnerable to XML External Entity injection.",
        "CWE-611",
    ),
    "flask_debug": (
        r'app\.run\s*\(.*debug\s*=\s*True',
        "medium",
        "Flask Debug Mode",
        "Flask debug mode enabled — exposes interactive debugger and should never run in production.",
        "CWE-94",
    ),
}

# Route-extraction patterns (info severity)
PYTHON_ROUTE_PATTERNS = {
    "flask_route": r'@(?:\w+\.)?(?:app|blueprint|bp)\.(?:route|get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
    "django_path": r'(?:re_)?path\s*\(\s*["\']([^"\']+)["\']',
    "django_url":  r'url\s*\(\s*r?["\']([^"\']+)["\']',
}

JS_VULN_PATTERNS = {
    "dom_xss": (
        r'document\.(write|innerHTML|outerHTML)\s*=',
        "high",
        "DOM XSS",
        "Direct assignment to innerHTML/outerHTML/document.write() with potentially user-controlled data.",
        "CWE-79",
    ),
    "eval_injection": (
        r'\beval\s*\(|new\s+Function\s*\(',
        "critical",
        "Eval Injection",
        "eval() or new Function() with dynamic content allows arbitrary JS execution.",
        "CWE-95",
    ),
    "prototype_pollution": (
        r'__proto__|Object\.assign\s*\(\s*\{\}',
        "medium",
        "Prototype Pollution",
        "Potential prototype pollution via __proto__ or unsafe Object.assign() usage.",
        "CWE-1321",
    ),
    "hardcoded_secret": (
        r'(?i)(apiKey|api_key|secret|password|token)\s*[:=]\s*["\'][^"\']{8,}["\']',
        "high",
        "Hardcoded Secret",
        "Secret or credential hardcoded in client-side JavaScript — visible to anyone who views source.",
        "CWE-798",
    ),
    "sql_injection": (
        r'db\.(query|execute)\s*\(`.*\$\{',
        "critical",
        "SQL Injection",
        "Template literal used inside a DB query — user-controlled data may inject SQL.",
        "CWE-89",
    ),
    "ssrf": (
        r'fetch\s*\(.*req\.(query|body|params)|axios\.(get|post)\s*\(.*req\.',
        "high",
        "SSRF",
        "Outbound HTTP request built from request parameters — may enable SSRF.",
        "CWE-918",
    ),
    "open_redirect": (
        r'res\.redirect\s*\(.*req\.(query|body|params)',
        "medium",
        "Open Redirect",
        "Redirect target derived from user input without validation.",
        "CWE-601",
    ),
}

JS_ROUTE_PATTERNS = {
    "express_route": r'(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*["\']([^"\']+)["\']',
    "fastify_route": r'fastify\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
}

JAVA_VULN_PATTERNS = {
    "hardcoded_creds": (
        r'(?i)(password|secret|apiKey|token)\s*=\s*"[^"]{8,}"',
        "high",
        "Hardcoded Credentials",
        "Credential hardcoded as a string literal in Java source.",
        "CWE-798",
    ),
    "sql_injection": (
        r'Statement.*execute.*\+|createStatement\(\).*\+',
        "critical",
        "SQL Injection",
        "String concatenation inside JDBC statement execution enables SQL injection.",
        "CWE-89",
    ),
    "insecure_random": (
        r'\bnew\s+java\.util\.Random\s*\(',
        "medium",
        "Insecure Randomness",
        "java.util.Random is not cryptographically secure — use SecureRandom for security-sensitive operations.",
        "CWE-330",
    ),
    "path_traversal": (
        r'new\s+File\s*\(.*\+|getResourceAsStream\s*\(.*\+',
        "high",
        "Path Traversal",
        "File path constructed with string concatenation may allow directory traversal.",
        "CWE-22",
    ),
    "xxe": (
        r'XMLInputFactory|DocumentBuilderFactory|SAXParserFactory',
        "high",
        "XXE",
        "XML parser instantiated without explicitly disabling external entity processing.",
        "CWE-611",
    ),
    "command_injection": (
        r'Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(.*\+',
        "critical",
        "Command Injection",
        "Runtime.exec or ProcessBuilder with string concatenation may allow OS command injection.",
        "CWE-78",
    ),
}

JAVA_ROUTE_PATTERNS = {
    "spring_request_mapping": r'@(?:Request|Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
}

GO_VULN_PATTERNS = {
    "sql_injection": (
        r'db\.(Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf',
        "critical",
        "SQL Injection",
        "fmt.Sprintf used to build a SQL query string — parameterized queries should be used instead.",
        "CWE-89",
    ),
    "command_injection": (
        r'exec\.Command\s*\([^)]*\+',
        "critical",
        "Command Injection",
        "exec.Command built with string concatenation — user input may inject shell commands.",
        "CWE-78",
    ),
    "hardcoded_secret": (
        r'(?i)(password|secret|key|token)\s*:?=\s*"[^"]{8,}"',
        "high",
        "Hardcoded Secret",
        "Sensitive value hardcoded as a Go string literal.",
        "CWE-798",
    ),
    "path_traversal": (
        r'os\.Open\s*\([^)]*\+|ioutil\.ReadFile\s*\([^)]*\+',
        "high",
        "Path Traversal",
        "File operation with dynamically-constructed path may allow directory traversal.",
        "CWE-22",
    ),
    "insecure_tls": (
        r'InsecureSkipVerify\s*:\s*true',
        "high",
        "Insecure TLS",
        "TLS certificate verification disabled — susceptible to MITM attacks.",
        "CWE-295",
    ),
}

GO_ROUTE_PATTERNS = {
    "http_handle_func": r'http\.HandleFunc\s*\(\s*["\']([^"\']+)["\']',
    "gin_route":        r'(?:r|router|engine)\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["\']([^"\']+)["\']',
    "echo_route":       r'e\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["\']([^"\']+)["\']',
}

# Extension → language mapping
EXT_LANG_MAP = {
    ".py":   "python",
    ".js":   "javascript",
    ".jsx":  "javascript",
    ".ts":   "javascript",
    ".tsx":  "javascript",
    ".mjs":  "javascript",
    ".java": "java",
    ".go":   "go",
}

# Directories to skip during traversal
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".idea", ".vscode", "vendor", "target",
}

# Sanitisation functions that neutralise taint
PYTHON_SANITISERS = {
    "escape", "quote", "sanitize", "sanitise", "encode",
    "parameterize", "parameterise", "htmlescape", "urlencode",
    "bleach.clean", "markupsafe.escape",
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SourceAnalysisEngine:
    """Multi-language static analysis engine."""

    def analyze_directory(self, path: str, languages: Optional[list] = None) -> SourceAnalysisResult:
        root = Path(path).resolve()
        if not root.exists():
            logger.error("Path does not exist: %s", root)
            return SourceAnalysisResult(target_path=str(root))

        result = SourceAnalysisResult(target_path=str(root))
        result.language_stats = self._count_languages(str(root))

        for file_path in self._iter_source_files(root):
            lang = self._detect_language(str(file_path))
            if languages and lang not in languages:
                continue
            if lang == "unknown":
                continue
            try:
                findings = self.analyze_file(str(file_path))
                result.findings.extend(findings)

                content = file_path.read_text(errors="replace")
                if lang == "python":
                    result.routes.extend(self._extract_routes_python(content, str(file_path)))
                    result.data_flows.extend(self._extract_data_flows_python(content, str(file_path)))
                elif lang == "javascript":
                    result.routes.extend(self._extract_routes_javascript(content, str(file_path)))
            except Exception as exc:
                logger.debug("Error analysing %s: %s", file_path, exc)

        return result

    def analyze_file(self, file_path: str) -> list:
        fp = Path(file_path)
        if not fp.is_file():
            return []
        lang = self._detect_language(file_path)
        try:
            content = fp.read_text(errors="replace")
        except Exception as exc:
            logger.debug("Cannot read %s: %s", file_path, exc)
            return []

        dispatch = {
            "python":     self._scan_python,
            "javascript": self._scan_javascript,
            "java":       self._scan_java,
            "go":         self._scan_go,
        }
        scanner = dispatch.get(lang)
        if scanner is None:
            return []
        findings = scanner(file_path, content)
        # Python AST taint check (supplementary)
        if lang == "python":
            findings.extend(self._check_python_ast(file_path, content))
        return findings

    # ------------------------------------------------------------------
    # Language detection
    # ------------------------------------------------------------------

    def _detect_language(self, file_path: str) -> str:
        ext = Path(file_path).suffix.lower()
        return EXT_LANG_MAP.get(ext, "unknown")

    # ------------------------------------------------------------------
    # Generic pattern scanner
    # ------------------------------------------------------------------

    def _scan_patterns(self, file_path: str, content: str, patterns: dict) -> list:
        findings = []
        lines = content.splitlines()
        for pattern_name, pattern_data in patterns.items():
            regex, severity, vuln_type, description, cwe_id = pattern_data
            for m in re.finditer(regex, content, re.IGNORECASE | re.MULTILINE):
                start = content[: m.start()].count("\n") + 1
                snippet = lines[start - 1].strip() if start <= len(lines) else m.group(0)
                findings.append(CodeFinding(
                    file_path=file_path,
                    line_number=start,
                    vuln_type=vuln_type,
                    severity=severity,
                    title=f"{vuln_type} detected ({pattern_name})",
                    code_snippet=snippet[:200],
                    description=description,
                    cwe_id=cwe_id,
                ))
        return findings

    # ------------------------------------------------------------------
    # Language-specific scanners
    # ------------------------------------------------------------------

    def _scan_python(self, file_path: str, content: str) -> list:
        findings = self._scan_patterns(file_path, content, PYTHON_VULN_PATTERNS)
        # Extra: check for xxe only when defusedxml is NOT imported
        if re.search(r'(?:xml\.etree|lxml\.etree)', content) and "defusedxml" not in content:
            for m in re.finditer(r'(?:xml\.etree|lxml\.etree)', content):
                lineno = content[: m.start()].count("\n") + 1
                lines = content.splitlines()
                snippet = lines[lineno - 1].strip() if lineno <= len(lines) else m.group(0)
                findings.append(CodeFinding(
                    file_path=file_path,
                    line_number=lineno,
                    vuln_type="XXE",
                    severity="medium",
                    title="Potential XXE — defusedxml not used",
                    code_snippet=snippet[:200],
                    description="XML parsed without defusedxml; external entity injection may be possible.",
                    cwe_id="CWE-611",
                ))
        return findings

    def _scan_javascript(self, file_path: str, content: str) -> list:
        return self._scan_patterns(file_path, content, JS_VULN_PATTERNS)

    def _scan_java(self, file_path: str, content: str) -> list:
        findings = self._scan_patterns(file_path, content, JAVA_VULN_PATTERNS)
        # Refined XXE: only flag if setFeature/setProperty disabling is absent
        if re.search(r'XMLInputFactory|DocumentBuilderFactory|SAXParserFactory', content):
            if not re.search(r'setFeature|setProperty|setExpandEntityReferences', content):
                for m in re.finditer(r'XMLInputFactory|DocumentBuilderFactory|SAXParserFactory', content):
                    lineno = content[: m.start()].count("\n") + 1
                    lines = content.splitlines()
                    snippet = lines[lineno - 1].strip() if lineno <= len(lines) else m.group(0)
                    findings.append(CodeFinding(
                        file_path=file_path,
                        line_number=lineno,
                        vuln_type="XXE",
                        severity="high",
                        title="XXE — XML parser without external entity disabling",
                        code_snippet=snippet[:200],
                        description="XML parser factory used without disabling external entity resolution (setFeature/setProperty).",
                        cwe_id="CWE-611",
                    ))
        return findings

    def _scan_go(self, file_path: str, content: str) -> list:
        return self._scan_patterns(file_path, content, GO_VULN_PATTERNS)

    # ------------------------------------------------------------------
    # Route extraction
    # ------------------------------------------------------------------

    def _extract_routes_python(self, content: str, file_path: str) -> list:
        routes = []
        lines = content.splitlines()

        # Flask / FastAPI style decorators
        flask_re = re.compile(
            r'@(?:\w+\.)?(?:app|blueprint|bp|router)\.'
            r'(route|get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        for m in flask_re.finditer(content):
            method_str = m.group(1).upper()
            route_path = m.group(2)
            lineno = content[: m.start()].count("\n") + 1
            # Look ahead for handler name
            handler = "unknown"
            for i in range(lineno, min(lineno + 3, len(lines))):
                hm = re.search(r'def\s+(\w+)\s*\(', lines[i])
                if hm:
                    handler = hm.group(1)
                    break
            method = "GET" if method_str == "ROUTE" else method_str
            auth = bool(re.search(r'login_required|jwt_required|requires_auth', "\n".join(lines[max(0, lineno - 1):lineno + 5])))
            params = re.findall(r'<(?:[^:>]+:)?([^>]+)>', route_path)
            routes.append(RouteInfo(
                path=route_path,
                method=method,
                handler=handler,
                file_path=file_path,
                line_number=lineno,
                auth_required=auth,
                params=params,
            ))

        # Django url/path
        django_re = re.compile(r'(?:re_)?path\s*\(\s*r?["\']([^"\']+)["\'].*?,\s*(\w[\w.]*)', re.IGNORECASE)
        for m in django_re.finditer(content):
            lineno = content[: m.start()].count("\n") + 1
            routes.append(RouteInfo(
                path=m.group(1),
                method="ANY",
                handler=m.group(2),
                file_path=file_path,
                line_number=lineno,
                auth_required=False,
                params=[],
            ))
        return routes

    def _extract_routes_javascript(self, content: str, file_path: str) -> list:
        routes = []
        for pattern_name, pattern in JS_ROUTE_PATTERNS.items():
            for m in re.finditer(pattern, content, re.IGNORECASE):
                lineno = content[: m.start()].count("\n") + 1
                if m.lastindex >= 2:
                    method = m.group(1).upper()
                    route_path = m.group(2)
                else:
                    method = "ANY"
                    route_path = m.group(1)
                params = re.findall(r':(\w+)', route_path)
                routes.append(RouteInfo(
                    path=route_path,
                    method=method,
                    handler="anonymous",
                    file_path=file_path,
                    line_number=lineno,
                    auth_required=False,
                    params=params,
                ))
        return routes

    # ------------------------------------------------------------------
    # Data flow extraction (Python only, simple taint)
    # ------------------------------------------------------------------

    def _extract_data_flows_python(self, content: str, file_path: str) -> list:
        flows = []
        # Identify user-input sources in the file
        source_patterns = [
            (r'request\.(args|form|json|data|values|files)\[', "request.args/form/json"),
            (r'request\.get_json\s*\(',                         "request.get_json()"),
            (r'flask\.request\.',                               "flask.request"),
            (r'input\s*\(',                                     "input()"),
            (r'sys\.argv',                                      "sys.argv"),
            (r'os\.environ\.get\s*\(',                          "os.environ.get()"),
        ]
        sink_patterns = [
            (r'\.execute\s*\(',          "db.execute()"),
            (r'os\.system\s*\(',         "os.system()"),
            (r'subprocess\.',            "subprocess"),
            (r'eval\s*\(',               "eval()"),
            (r'open\s*\(',               "open()"),
            (r'requests\.(get|post)\s*\(', "requests.get/post()"),
            (r'pickle\.loads?\s*\(',     "pickle.load()"),
        ]
        lines = content.splitlines()
        for src_re, src_label in source_patterns:
            for sm in re.finditer(src_re, content):
                src_line = content[: sm.start()].count("\n") + 1
                # Search sinks in the following 30 lines
                search_block = "\n".join(lines[src_line: src_line + 30])
                for snk_re, snk_label in sink_patterns:
                    if re.search(snk_re, search_block):
                        # Check for sanitisation in the block
                        sanitized = any(s in search_block.lower() for s in PYTHON_SANITISERS)
                        flows.append(DataFlow(
                            source=f"{src_label} (line {src_line})",
                            sink=snk_label,
                            passes_through=[],
                            sanitized=sanitized,
                        ))
        return flows

    # ------------------------------------------------------------------
    # AST-based taint tracking (Python)
    # ------------------------------------------------------------------

    def _check_python_ast(self, file_path: str, content: str) -> list:
        findings = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        dangerous_calls = {
            "eval":        ("Eval Injection",          "critical", "CWE-95"),
            "exec":        ("Exec Injection",          "critical", "CWE-95"),
            "compile":     ("Dynamic Code Compilation","high",     "CWE-95"),
            "pickle.loads":("Insecure Deserialization","high",     "CWE-502"),
            "os.system":   ("Command Injection",       "critical", "CWE-78"),
            "subprocess.call": ("Command Injection",   "critical", "CWE-78"),
        }

        class TaintVisitor(ast.NodeVisitor):
            def __init__(self):
                self.tainted_names: set = set()
                self.found: list = []

            def visit_Assign(self, node):
                # If RHS looks like request.* treat as tainted
                if isinstance(node.value, ast.Attribute):
                    if isinstance(node.value.value, ast.Name) and node.value.value.id == "request":
                        for t in node.targets:
                            if isinstance(t, ast.Name):
                                self.tainted_names.add(t.id)
                self.generic_visit(node)

            def visit_Call(self, node):
                func_name = self._call_name(node)
                if func_name in dangerous_calls:
                    for arg in node.args:
                        if self._is_tainted(arg):
                            title, severity, cwe = dangerous_calls[func_name]
                            self.found.append((node.lineno, func_name, title, severity, cwe))
                self.generic_visit(node)

            def _call_name(self, node):
                if isinstance(node.func, ast.Name):
                    return node.func.id
                if isinstance(node.func, ast.Attribute):
                    parts = []
                    n = node.func
                    while isinstance(n, ast.Attribute):
                        parts.append(n.attr)
                        n = n.value
                    if isinstance(n, ast.Name):
                        parts.append(n.id)
                    return ".".join(reversed(parts))
                return ""

            def _is_tainted(self, node):
                if isinstance(node, ast.Name):
                    return node.id in self.tainted_names
                if isinstance(node, ast.JoinedStr):  # f-string
                    return any(self._is_tainted(v) for v in ast.walk(node) if isinstance(v, ast.Name))
                if isinstance(node, ast.BinOp):
                    return self._is_tainted(node.left) or self._is_tainted(node.right)
                return False

        visitor = TaintVisitor()
        visitor.visit(tree)
        lines = content.splitlines()
        for lineno, func_name, title, severity, cwe in visitor.found:
            snippet = lines[lineno - 1].strip() if lineno <= len(lines) else ""
            findings.append(CodeFinding(
                file_path=file_path,
                line_number=lineno,
                vuln_type=title,
                severity=severity,
                title=f"[AST] Tainted data flows into {func_name}()",
                code_snippet=snippet[:200],
                description=f"AST taint analysis: user-controlled value reaches {func_name}() without sanitisation.",
                cwe_id=cwe,
            ))
        return findings

    # ------------------------------------------------------------------
    # Language count
    # ------------------------------------------------------------------

    def _count_languages(self, path: str) -> dict:
        counts: dict = {}
        for fp in self._iter_source_files(Path(path)):
            lang = self._detect_language(str(fp))
            counts[lang] = counts.get(lang, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # File iterator
    # ------------------------------------------------------------------

    def _iter_source_files(self, root: Path):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                fp = Path(dirpath) / fname
                if fp.suffix.lower() in EXT_LANG_MAP:
                    yield fp


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

source_analysis_engine = SourceAnalysisEngine()
