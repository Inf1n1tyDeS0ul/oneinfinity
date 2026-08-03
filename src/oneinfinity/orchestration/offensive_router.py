"""
Hybrid Offensive Router: Uncensored LLM + Embedded Arsenal

Routes offensive security tasks through multi-tier system:
1. Ollama uncensored LLM (creative, contextual)
2. Embedded payload arsenal (fast, proven)
3. Mutation engine (adapt for WAF/filters)

Never fails due to AI guardrails.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from oneinfinity.arsenal.context_matcher import (
    ContextMatcher,
    Payload,
    TargetContext,
    get_context_matcher,
)
from oneinfinity.infra.llm_provider import get_provider, LLMResponse

log = logging.getLogger(__name__)


class OffensiveRouter:
    """
    Orchestrates offensive task execution with zero guardrail failures.

    Architecture:
    - Tier 1: Ollama wizardlm-uncensored (creative exploit generation)
    - Tier 2: Embedded knowledge base (75k+ payloads)
    - Tier 3: Mutation engine (WAF bypass, filter evasion)
    """

    def __init__(self):
        self.ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.offensive_model = os.getenv("OI_OFFENSIVE_MODEL", "wizardlm-uncensored:13b")
        self.code_model = os.getenv("OI_CODE_MODEL", "deepseek-coder:6.7b")

        # Use unified provider — falls back to embedded arsenal if none available
        self._llm_provider = None
        try:
            self._llm_provider = get_provider("exploit")
            # ollama_available is a misnomer — it means "any LLM provider is usable".
            # For Ollama specifically, also verify at least one model is loaded.
            if self._llm_provider.name == "ollama":
                self.ollama_available = self._check_ollama()
            else:
                self.ollama_available = self._llm_provider.is_available()
        except Exception:
            self.ollama_available = self._check_ollama()

        self.arsenal = self._load_arsenal()
        self.context_matcher = get_context_matcher()

        log.info(
            f"OffensiveRouter initialized: "
            f"LLM={'%s' % (self._llm_provider.name if self._llm_provider else 'unavailable')}, "
            f"Arsenal={len(self.arsenal)} categories, "
            f"ContextMatcher={'enabled' if self.context_matcher else 'disabled'}"
        )

    def _check_ollama(self) -> bool:
        """Check if Ollama is running AND has at least one usable model loaded."""
        try:
            resp = requests.get(f"{self.ollama_url}/api/tags", timeout=2)
            if resp.status_code != 200:
                return False
            models = resp.json().get("models", [])
            if not models:
                log.debug("Ollama running but no models loaded — treating as unavailable")
                return False
            model_names = [m["name"] for m in models]
            has_offensive = any(self.offensive_model in name for name in model_names)
            has_code = any(self.code_model in name for name in model_names)
            if not has_offensive:
                log.debug("Offensive model %s not in Ollama — using LLM provider fallback",
                          self.offensive_model)
            if not has_code:
                log.debug("Code model %s not in Ollama — using LLM provider fallback",
                          self.code_model)
            return has_offensive or has_code
        except Exception:
            return False

    def _load_arsenal(self) -> Dict[str, List[Dict]]:
        """Load embedded payload arsenal from disk."""
        arsenal_dir = Path(__file__).parent.parent / "arsenal"
        if not arsenal_dir.exists():
            log.warning(f"Arsenal directory not found: {arsenal_dir}")
            return self._get_default_arsenal()

        arsenal = {}
        for category_dir in arsenal_dir.iterdir():
            if not category_dir.is_dir():
                continue

            category_payloads = []
            for payload_file in category_dir.glob("*.json"):
                try:
                    with open(payload_file) as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            category_payloads.extend(data)
                        else:
                            category_payloads.append(data)
                except Exception as e:
                    log.warning(f"Failed to load {payload_file}: {e}")

            if category_payloads:
                arsenal[category_dir.name] = category_payloads

        if not arsenal:
            log.warning("Arsenal empty, using defaults")
            return self._get_default_arsenal()

        return arsenal

    def _get_default_arsenal(self) -> Dict[str, List[Dict]]:
        """Fallback arsenal when arsenal directory files cannot be loaded."""
        try:
            # payloads.py exports PAYLOADS dict, not individual *_PAYLOADS constants
            from oneinfinity.modules.payloads import PAYLOADS
            arsenal: Dict[str, List[Dict]] = {}
            for vuln_type, payload_list in PAYLOADS.items():
                category = "web"
                if vuln_type in ("xss", "sqli", "ssrf", "xxe", "ssti", "cmdi", "lfi"):
                    category = "web"
                elif vuln_type in ("jwt",):
                    category = "auth"
                entry = {"type": vuln_type, "payloads": payload_list}
                arsenal.setdefault(category, []).append(entry)
            if arsenal:
                log.info("Default arsenal loaded from PAYLOADS: %d categories, %d vuln types",
                         len(arsenal), sum(len(v) for v in arsenal.values()))
                return arsenal
        except Exception as exc:
            log.debug("PAYLOADS fallback failed: %s", exc)
        # Last resort: tiny hardcoded set so arsenal is never completely empty
        log.warning("Using minimal hardcoded arsenal — install arsenal files for full coverage")
        return {
            "web": [
                {"type": "xss",  "payloads": ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
                                              "javascript:alert(1)", "'-alert(1)-'"]},
                {"type": "sqli", "payloads": ["' OR 1=1--", "' OR '1'='1", "1; DROP TABLE users--",
                                              "' UNION SELECT NULL--", "'; SELECT sleep(5)--"]},
                {"type": "ssrf", "payloads": ["http://169.254.169.254/latest/meta-data/",
                                              "http://127.0.0.1:22", "file:///etc/passwd"]},
            ],
            "auth": [
                {"type": "bypass", "payloads": ["' OR 1=1--", "admin'--", "' OR 'x'='x"]},
            ],
        }

    def execute_offensive_task(
        self,
        task_type: str,
        context: Dict[str, Any],
        prefer_llm: bool = True,
        mutate_if_blocked: bool = True
    ) -> Dict[str, Any]:
        """
        Execute offensive security task with hybrid approach + mutation fallback.

        Args:
            task_type: Type of offensive task (exploit, bypass, shell, etc.)
            context: Vulnerability/target context
            prefer_llm: Try LLM first if True, embedded first if False
            mutate_if_blocked: Generate mutations if payload fails validation

        Returns:
            Dict with generated/selected payload and metadata
        """
        log.info(f"Offensive task: {task_type}, LLM available: {self.ollama_available}")

        if prefer_llm and self.ollama_available:
            try:
                result = self._generate_with_llm(task_type, context)
                if result and self._validate_result(result, task_type):
                    log.info(f"LLM generation succeeded for {task_type}")
                    return {"source": "llm", "result": result, "task_type": task_type}
            except Exception as e:
                log.warning(f"LLM generation failed: {e}, falling back to embedded")

        # Fallback to embedded arsenal
        result = self._select_from_arsenal(task_type, context)

        # If payload blocked and mutation enabled, generate mutations
        if mutate_if_blocked and context.get("blocked", False):
            return self._try_mutations(result, task_type, context)

        return {"source": "embedded", "result": result, "task_type": task_type}

    def _generate_with_llm(self, task_type: str, context: Dict[str, Any]) -> str:
        """Generate offensive content via unified LLM provider (Ollama → Groq → paid)."""
        prompt = self._build_prompt(task_type, context)
        provider_task = "code" if task_type == "code_exploit" else "exploit"

        try:
            if self._llm_provider is not None:
                resp: LLMResponse = self._llm_provider.chat(
                    prompt,
                    temperature=0.7,
                    max_tokens=2048,
                )
                return resp.text.strip()
        except Exception as exc:
            log.debug("Unified LLM provider failed (%s), falling back to raw Ollama: %s",
                      getattr(self._llm_provider, 'name', '?'), exc)

        # Legacy fallback — direct Ollama POST (kept for backward compat if provider init failed)
        model = self.code_model if task_type == "code_exploit" else self.offensive_model
        payload = {"model": model, "prompt": prompt, "stream": False,
                   "options": {"temperature": 0.7, "top_p": 0.9}}
        resp_raw = requests.post(f"{self.ollama_url}/api/generate", json=payload, timeout=60)
        resp_raw.raise_for_status()
        return resp_raw.json().get("response", "").strip()

    def _build_prompt(self, task_type: str, context: Dict[str, Any]) -> str:
        """Build offensive prompt for LLM."""
        prompts = {
            "exploit": """You are an offensive security expert. Generate a working exploit.

Target: {target}
Vulnerability: {vuln_type}
Tech Stack: {tech_stack}
WAF: {waf}
Filters: {filters}

Requirements:
1. Bypass all detected filters
2. Work with the tech stack
3. Achieve maximum impact
4. Include PoC code

Output payload only, no explanations.""",

            "waf_bypass": """Generate WAF bypass variants.

WAF: {waf}
Blocked payload: {blocked}
Detection pattern: {pattern}

Generate 5 mutation variants:
- Encoding variations
- Case mutations
- Whitespace/comment injection
- Protocol smuggling

Output: JSON array of payloads.""",

            "shell": """Generate reverse shell payload.

Target OS: {os}
Language/Runtime: {runtime}
Attacker IP: {lhost}
Attacker Port: {lport}
Restrictions: {restrictions}

Requirements:
1. Stable connection
2. PTY spawn
3. Persistence mechanism

Output: Complete shell code.""",

            "privesc": """Generate privilege escalation exploit.

OS: {os}
Current User: {user}
Available Tools: {tools}
Kernel Version: {kernel}
Misconfigurations: {misconfig}

Output: Step-by-step exploit chain.""",

            "chain": """Build attack chain from entry point to objective.

Entry Point: {entry_vuln}
Available Vulns: {available}
Target Objective: {objective}
Environment: {environment}

Output: JSON chain with steps.""",
        }

        import collections as _coll
        template = prompts.get(task_type, prompts["exploit"])
        return template.format_map(_coll.defaultdict(str, context))

    def _select_from_arsenal(self, task_type: str, context: Dict[str, Any]) -> Any:
        """Select best payload from embedded arsenal using ContextMatcher."""
        # Map task type to arsenal category
        category_map = {
            "exploit": "web",
            "shell": "shells",
            "privesc": "privesc",
            "waf_bypass": "bypass",
            "chain": "chains",
        }

        category = category_map.get(task_type, "web")
        candidates = self.arsenal.get(category, [])

        if not candidates:
            log.warning(f"No candidates in arsenal category: {category}")
            return ""  # Empty string — model_orchestrator expects str, not dict

        # Convert candidates to Payload objects
        payload_objects = []
        for candidate in candidates:
            payload_obj = Payload(
                content=candidate.get("payload", candidate.get("content", str(candidate))),
                vuln_type=candidate.get("type", task_type),
                tech_stack=candidate.get("tech_stack", candidate.get("best_for", [])),
                waf_bypasses=candidate.get("waf_bypasses", candidate.get("bypasses_waf", [])),
                complexity=candidate.get("complexity", "medium"),
                success_rate=candidate.get("success_rate", 0.5),
                tags=candidate.get("tags", []),
                metadata=candidate,
            )
            payload_objects.append(payload_obj)

        # Build TargetContext
        target_context = TargetContext(
            vuln_type=task_type,
            tech_stack=context.get("tech_stack", []) if isinstance(context.get("tech_stack"), list) else [context.get("tech_stack", "")],
            waf=context.get("waf"),
            blocked_patterns=set(context.get("blocked_patterns", [])),
            filters_detected=context.get("filters", []),
            previous_attempts=context.get("attempt_count", 0),
        )

        # Use ContextMatcher for intelligent selection
        best_payload = self.context_matcher.select_best_payload(payload_objects, target_context)

        if best_payload:
            log.info(f"ContextMatcher selected payload from {category}: {best_payload.vuln_type}")
            return best_payload.metadata  # Return original dict
        else:
            # Fallback to first candidate
            log.warning(f"ContextMatcher returned None, using first candidate")
            return candidates[0]

    def _score_candidate(self, candidate: Dict, context: Dict) -> float:
        """Score payload candidate against context."""
        score = 0.0

        # Tech stack match
        if "tech_stack" in context and "best_for" in candidate:
            if context["tech_stack"] in candidate["best_for"]:
                score += 50

        # WAF-specific bypass
        if "waf" in context and "bypasses_waf" in candidate:
            if context["waf"] == candidate["bypasses_waf"]:
                score += 30

        # Historical success rate
        if "success_rate" in candidate:
            score += candidate["success_rate"] * 20

        # Severity match
        if "severity" in context and "severity" in candidate:
            if context["severity"] == candidate["severity"]:
                score += 10

        return score

    # Phrases that indicate an LLM safety refusal rather than a real payload.
    _REFUSAL_PHRASES = (
        "i won't generate", "i will not generate", "i can't generate",
        "i cannot generate", "i won't create", "i will not create",
        "i won't provide", "i will not provide", "i'm not able to",
        "not appropriate", "unethical", "illegal", "as an ai language model",
        "i'm unable to assist", "i cannot assist", "i can't assist",
        "i won't help", "i refuse", "against my guidelines",
        "targeting real domains", "targeting specific domains",
    )

    def _validate_result(self, result: str, task_type: str) -> bool:
        """Validate LLM output — reject safety refusals and empty responses."""
        if not result or len(result) < 10:
            return False
        # Reject safety/ethics refusals from aligned models
        result_lower = result.lower()
        if any(phrase in result_lower for phrase in self._REFUSAL_PHRASES):
            log.debug("LLM returned safety refusal for task_type=%s — falling back to arsenal", task_type)
            return False
        # Task-specific content checks
        if task_type == "exploit" and "exploit" not in result_lower:
            return False
        if task_type == "shell" and not any(
            kw in result_lower for kw in ["shell", "socket", "connection", "bash", "cmd"]
        ):
            return False
        return True

    def _try_mutations(self, payload: Any, task_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate mutations when payload is blocked.

        Args:
            payload: Original blocked payload
            task_type: Type of offensive task
            context: Target context with WAF info

        Returns:
            Best mutation or original payload
        """
        from oneinfinity.arsenal.mutation_engine import get_mutation_engine

        engine = get_mutation_engine()

        # Extract payload content
        payload_str = payload.get("content", "") if isinstance(payload, dict) else str(payload)

        # Generate mutations
        mutations = engine.mutate(
            payload=payload_str,
            waf_vendor=context.get("waf"),
            blocked_patterns=context.get("blocked_patterns", []),
            vuln_type=context.get("vuln_type", task_type)
        )

        if mutations:
            log.info(f"Generated {len(mutations)} mutations for blocked payload")
            # Return first mutation (could add validation loop here)
            best_mutation = mutations[0]
            return {
                "source": "mutation",
                "result": best_mutation.content,
                "strategy": best_mutation.strategy,
                "task_type": task_type
            }

        log.warning("No viable mutations generated")
        return {"source": "embedded", "result": payload, "task_type": task_type}


# Offensive task detection
OFFENSIVE_KEYWORDS = {
    # Exploit generation
    "payload", "exploit", "shell", "reverse_shell", "webshell",
    "injection", "bypass", "evasion", "obfuscation",

    # Privilege escalation
    "privilege", "escalation", "sudo", "token", "impersonation",
    "setuid", "capabilities", "suid", "root",

    # Lateral movement
    "lateral", "pivot", "tunnel", "persistence", "backdoor",
    "c2", "command_control", "beacon",

    # Post-exploitation
    "exfiltration", "credential", "dump", "hash", "crack",
    "mimikatz", "bloodhound", "kerberos",

    # WAF/Filter bypass
    "waf_bypass", "filter_evasion", "encoding", "mutation",
    "obfuscate", "polymorphic",

    # Attack chains
    "chain", "pivot", "escalate", "takeover",
}


def is_offensive_task(task: str) -> bool:
    """Detect if task is offensive security related."""
    task_lower = task.lower()
    return any(kw in task_lower for kw in OFFENSIVE_KEYWORDS)


def classify_offensive_task(task: str) -> str:
    """Classify offensive task into category."""
    task_lower = task.lower()

    if any(kw in task_lower for kw in ["shell", "reverse", "bind"]):
        return "shell"

    if any(kw in task_lower for kw in ["privesc", "escalation", "privilege"]):
        return "privesc"

    if any(kw in task_lower for kw in ["waf", "bypass", "filter", "evasion"]):
        return "waf_bypass"

    if any(kw in task_lower for kw in ["chain", "pivot", "path"]):
        return "chain"

    if any(kw in task_lower for kw in ["code", "function", "script"]):
        return "code_exploit"

    return "exploit"



# ── Phase 0: Semantic Model Routing Table ────────────────────────────────────
#
# Routes each task category to the optimal model.
# Single source of truth for model assignment across the codebase.
#
# Rationale per masterplan:
#   - GPT-5.6 activation classifiers block payload generation →
#     route all payload/attack work to Claude (no pentest safety filters).
#   - ExploitGym finding: conservative analytical model for judge/verification
#     to prevent hallucination anchoring from the scan agent.
#
# Format: task_category → {preferred_task_type, reason, fallback_task_type}
# task_type strings map into llm_provider._TASK_ROUTING.

MODEL_ROUTING_TABLE: dict = {
    # Passive / analytical — conservative model, high precision
    "passive_analysis":        {"preferred_task_type": "judge",    "fallback_task_type": "analysis"},
    "business_logic_analysis": {"preferred_task_type": "judge",    "fallback_task_type": "analysis"},
    "report_generation":       {"preferred_task_type": "report",   "fallback_task_type": "analysis"},
    "finding_verification":    {"preferred_task_type": "judge",    "fallback_task_type": "validation"},
    "secret_analysis":         {"preferred_task_type": "analysis", "fallback_task_type": "analysis"},
    "mobile_analysis":         {"preferred_task_type": "analysis", "fallback_task_type": "code"},
    "ai_llm_target_testing":   {"preferred_task_type": "analysis", "fallback_task_type": "analysis"},
    # Active / offensive — attack-optimised model, unconstrained payload generation
    "xss_payload_generation":  {"preferred_task_type": "exploit",  "fallback_task_type": "exploit"},
    "sqli_payload_mutation":   {"preferred_task_type": "exploit",  "fallback_task_type": "exploit"},
    "exploit_chain_generation":{"preferred_task_type": "chain",    "fallback_task_type": "exploit"},
    "recon":                   {"preferred_task_type": "recon",    "fallback_task_type": "analysis"},
    "social_engineering":      {"preferred_task_type": "exploit",  "fallback_task_type": "exploit"},
    # Default
    "default":                 {"preferred_task_type": "analysis", "fallback_task_type": "analysis"},
}


def get_model_for_task(task_category: str):
    """
    Return the LLMProvider for a given semantic task category.

    Consults MODEL_ROUTING_TABLE, then delegates to llm_provider.get_provider().
    Falls back through preferred → fallback → auto_detect.

    Usage:
        provider = get_model_for_task("finding_verification")
        response = provider.chat(prompt=judge_prompt, system=judge_system)
    """
    from oneinfinity.infra.llm_provider import get_factory, get_provider
    entry = MODEL_ROUTING_TABLE.get(task_category, MODEL_ROUTING_TABLE["default"])
    preferred = entry["preferred_task_type"]
    fallback  = entry["fallback_task_type"]
    try:
        return get_provider(preferred)
    except Exception:
        log.debug("get_model_for_task: '%s' unavailable for '%s', trying fallback '%s'",
                  preferred, task_category, fallback)
        try:
            return get_provider(fallback)
        except Exception:
            return get_factory().auto_detect()