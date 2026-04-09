"""Business Logic Attack Engine — LLM-driven hypothesis generation with rule-based fallback."""
from __future__ import annotations
import asyncio
import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

ATTACK_CATEGORIES = [
    "price_manipulation",
    "workflow_bypass",
    "race_condition",
    "mass_assignment",
    "coupon_abuse",
    "privilege_escalation",
    "business_rule_bypass",
    "negative_value_attack",
    "replay_attack",
    "state_confusion",
]

RULE_BASED_TEMPLATES: Dict[str, List[Dict]] = {
    "price_manipulation": [
        {"technique": "negative_price",
         "description": "Submit negative price/quantity values in checkout",
         "payload_hint": '{"price": -9999, "quantity": -1}', "severity": "high"},
        {"technique": "price_parameter_tamper",
         "description": "Modify hidden price fields in POST body",
         "payload_hint": "price=0.01&total=0.01", "severity": "high"},
        {"technique": "integer_overflow",
         "description": "Send MAX_INT quantity to trigger overflow discount",
         "payload_hint": '{"quantity": 2147483647}', "severity": "medium"},
    ],
    "workflow_bypass": [
        {"technique": "step_skip",
         "description": "Jump directly to final step skipping validation",
         "payload_hint": "POST /checkout/complete without /checkout/payment",
         "severity": "high"},
        {"technique": "state_manipulation",
         "description": "Replay step-1 token in step-3 request",
         "payload_hint": "Reuse CSRF token from earlier step", "severity": "medium"},
        {"technique": "forced_browsing",
         "description": "Direct access to protected workflow URLs",
         "payload_hint": "GET /admin/confirm without completing previous steps",
         "severity": "high"},
    ],
    "race_condition": [
        {"technique": "parallel_redemption",
         "description": "Send 50 concurrent coupon redemption requests",
         "payload_hint": "Use asyncio to send simultaneous requests", "severity": "high"},
        {"technique": "toctou_balance",
         "description": "Race between balance check and deduction",
         "payload_hint": "Concurrent withdraw requests exceeding balance",
         "severity": "critical"},
        {"technique": "duplicate_transaction",
         "description": "Double-submit payment in parallel",
         "payload_hint": "Two simultaneous POST /payment with same idempotency key",
         "severity": "high"},
    ],
    "mass_assignment": [
        {"technique": "role_elevation",
         "description": "Add role/admin field to registration payload",
         "payload_hint": '{"username":"x","password":"x","role":"admin","is_admin":true}',
         "severity": "critical"},
        {"technique": "balance_injection",
         "description": "Inject balance/credits in update profile request",
         "payload_hint": '{"email":"x@x.com","balance":99999,"credits":9999}',
         "severity": "high"},
        {"technique": "hidden_field_injection",
         "description": "Add undocumented fields from API schema",
         "payload_hint": '{"verified":true,"subscription":"premium","trial_days":365}',
         "severity": "medium"},
    ],
    "coupon_abuse": [
        {"technique": "coupon_reuse",
         "description": "Reuse single-use coupon after successful redemption",
         "payload_hint": "Apply same coupon code after order completion",
         "severity": "medium"},
        {"technique": "coupon_stacking",
         "description": "Apply multiple exclusive coupons simultaneously",
         "payload_hint": "Add two coupon fields to same request", "severity": "medium"},
        {"technique": "negative_coupon",
         "description": "Craft coupon with negative discount value",
         "payload_hint": '{"coupon": "SAVE10", "discount": -500}', "severity": "high"},
    ],
}


@dataclass
class BusinessLogicAttack:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    category: str = ""
    technique: str = ""
    description: str = ""
    payload_hint: str = ""
    severity: str = "medium"
    target_endpoint: str = ""
    test_steps: List[str] = field(default_factory=list)
    expected_behavior: str = ""
    vulnerable_behavior: str = ""
    source: str = "rule_based"

    def to_dict(self) -> dict:
        return {
            "id": self.id, "category": self.category,
            "technique": self.technique, "description": self.description,
            "payload_hint": self.payload_hint, "severity": self.severity,
            "target_endpoint": self.target_endpoint,
            "test_steps": self.test_steps,
            "expected_behavior": self.expected_behavior,
            "vulnerable_behavior": self.vulnerable_behavior,
            "source": self.source,
        }


class BusinessLogicAttackEngine:
    """Generates business logic attack hypotheses using LLM + rule-based fallback."""

    def __init__(self):
        self._openai_key = os.getenv("OPENAI_API_KEY", "")
        self._llm_available = HAS_OPENAI and bool(self._openai_key)

    async def generate(
        self,
        target: str,
        app_context: Optional[Dict] = None,
        categories: Optional[List[str]] = None,
    ) -> List[BusinessLogicAttack]:
        cats = categories or ATTACK_CATEGORIES
        attacks: List[BusinessLogicAttack] = []

        if self._llm_available and app_context:
            try:
                llm_attacks = await self._llm_generate(target, app_context, cats)
                attacks.extend(llm_attacks)
            except Exception:
                pass

        rule_attacks = self._rule_based_generate(target, cats)
        attacks.extend(rule_attacks)

        seen: set = set()
        deduped = []
        for a in attacks:
            key = f"{a.category}:{a.technique}"
            if key not in seen:
                seen.add(key)
                deduped.append(a)
        return deduped

    def _rule_based_generate(self, target: str, categories: List[str]) -> List[BusinessLogicAttack]:
        attacks = []
        for cat in categories:
            for t in RULE_BASED_TEMPLATES.get(cat, []):
                a = BusinessLogicAttack(
                    category=cat,
                    technique=t["technique"],
                    description=t["description"],
                    payload_hint=t["payload_hint"],
                    severity=t["severity"],
                    target_endpoint=f"https://{target}",
                    test_steps=self._build_test_steps(cat, t),
                    expected_behavior="Request rejected / no unintended effect",
                    vulnerable_behavior="Unintended discount / privilege / resource access",
                    source="rule_based",
                )
                attacks.append(a)
        return attacks

    def _build_test_steps(self, category: str, template: dict) -> List[str]:
        steps = [
            f"1. Identify target endpoint handling {category.replace('_', ' ')}",
            "2. Intercept normal request with Burp Suite",
            f"3. Modify payload: {template['payload_hint']}",
            "4. Send modified request and observe response",
            "5. Compare response with legitimate request behavior",
        ]
        if category == "race_condition":
            steps.append("6. Use Turbo Intruder or asyncio to send parallel requests")
        return steps

    async def _llm_generate(
        self, target: str, app_context: dict, categories: List[str]
    ) -> List[BusinessLogicAttack]:
        if not HAS_OPENAI:
            return []
        context_str = json.dumps(app_context, indent=2)[:2000]
        prompt = (
            f"You are an offensive security expert specializing in business logic vulnerabilities.\n\n"
            f"Target: {target}\nApplication Context:\n{context_str}\n\n"
            f"Generate 3 high-impact business logic attack scenarios for categories: "
            f"{', '.join(categories[:5])}.\n\n"
            "Return JSON array with objects: category, technique, description, payload_hint, "
            "severity, target_endpoint, test_steps (array), expected_behavior, vulnerable_behavior.\n"
            "Return only valid JSON array."
        )
        client = openai.AsyncOpenAI(api_key=self._openai_key)
        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=1500,
        )
        content = response.choices[0].message.content.strip()
        content = content.lstrip("```json").lstrip("```").rstrip("```").strip()
        items = json.loads(content)
        attacks = []
        for item in items:
            a = BusinessLogicAttack(
                category=item.get("category", "workflow_bypass"),
                technique=item.get("technique", "llm_generated"),
                description=item.get("description", ""),
                payload_hint=item.get("payload_hint", ""),
                severity=item.get("severity", "medium"),
                target_endpoint=item.get("target_endpoint", f"https://{target}"),
                test_steps=item.get("test_steps", []),
                expected_behavior=item.get("expected_behavior", ""),
                vulnerable_behavior=item.get("vulnerable_behavior", ""),
                source="llm",
            )
            attacks.append(a)
        return attacks
