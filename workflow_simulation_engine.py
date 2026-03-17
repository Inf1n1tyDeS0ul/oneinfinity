"""
workflow_simulation_engine.py — Business Logic Workflow Simulation

Models user workflows as state machines and systematically generates
and executes business logic attacks against each workflow step.

Built-in workflows:
  - checkout_flow         (add to cart → apply coupon → pay → confirm)
  - login_flow            (enter creds → MFA → dashboard)
  - password_reset_flow   (request reset → verify token → set new password)
  - account_creation_flow (register → verify email → set profile)
  - fund_transfer_flow    (select recipient → enter amount → confirm → 2FA)
  - subscription_flow     (choose plan → checkout → activate)
  - file_upload_flow      (select file → validate → store → serve)

Built-in attack categories:
  - price_manipulation      (negative / zero / fractional prices)
  - coupon_stacking         (multiple codes, expired codes, replay)
  - workflow_step_skip      (jump directly to final step)
  - race_condition          (concurrent identical requests)
  - parameter_tampering     (modify hidden / read-only fields)
  - privilege_escalation    (inject role/admin fields mid-flow)
  - negative_quantity       (negative item counts)
  - integer_overflow        (boundary values)
  - response_manipulation   (modify server response client-side — doc only)

Usage:
    engine = WorkflowSimulationEngine(base_url="https://example.com")
    results = asyncio.run(engine.simulate_workflow("checkout_flow", session=...))
    for finding in results.findings:
        print(finding.title)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Optional platform imports ─────────────────────────────────────────────────

try:
    from swarm_intelligence_engine import AgentFinding, AgentType
    _SWARM_AVAILABLE = True
except ImportError:
    _SWARM_AVAILABLE = False
    AgentFinding = None  # type: ignore
    AgentType    = None  # type: ignore

try:
    from modules.tool_wrappers import ToolRegistry
    _TOOLS_AVAILABLE = True
except ImportError:
    _TOOLS_AVAILABLE = False
    ToolRegistry = None  # type: ignore


# ── Enumerations ──────────────────────────────────────────────────────────────

class AttackCategory(str, Enum):
    PRICE_MANIPULATION    = "price_manipulation"
    COUPON_STACKING       = "coupon_stacking"
    WORKFLOW_STEP_SKIP    = "workflow_step_skip"
    RACE_CONDITION        = "race_condition"
    PARAMETER_TAMPERING   = "parameter_tampering"
    PRIVILEGE_ESCALATION  = "privilege_escalation"
    NEGATIVE_QUANTITY     = "negative_quantity"
    INTEGER_OVERFLOW      = "integer_overflow"
    REPLAY_ATTACK         = "replay_attack"

class StepStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    PASSED    = "passed"
    FAILED    = "failed"
    SKIPPED   = "skipped"
    ATTACKED  = "attacked"


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class WorkflowStep:
    """A single step in a multi-step user workflow."""
    step_id:         str
    name:            str
    method:          str              # GET / POST / PUT / DELETE / PATCH
    endpoint:        str              # relative or absolute URL
    params:          Dict[str, Any]   # request body / query params
    expected_status: List[int]        = field(default_factory=lambda: [200, 201, 302])
    assertions:      List[str]        = field(default_factory=list)  # strings expected in body
    extract_vars:    Dict[str, str]   = field(default_factory=dict)  # var_name → jsonpath/regex
    optional:        bool             = False
    delay_after_s:   float            = 0.0

    def clone(self, **overrides) -> "WorkflowStep":
        import copy
        s = copy.deepcopy(self)
        for k, v in overrides.items():
            setattr(s, k, v)
        return s


@dataclass
class Workflow:
    """Ordered sequence of steps representing a complete user journey."""
    name:        str
    description: str
    steps:       List[WorkflowStep]
    session_vars: Dict[str, Any] = field(default_factory=dict)
    tags:        List[str]       = field(default_factory=list)


@dataclass
class WorkflowAttack:
    """A mutated workflow variant designed to probe a specific flaw."""
    attack_id:       str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    category:        AttackCategory = AttackCategory.PARAMETER_TAMPERING
    workflow_name:   str = ""
    description:     str = ""
    modified_steps:  List[WorkflowStep] = field(default_factory=list)
    skipped_steps:   List[str]          = field(default_factory=list)
    injected_params: Dict[str, Any]     = field(default_factory=dict)
    expected_vuln:   str                = ""
    severity:        str                = "high"
    cvss:            float              = 7.5


@dataclass
class StepResult:
    step_id:    str
    name:       str
    status:     StepStatus
    http_status: int           = 0
    body:        str           = ""
    extracted:   Dict[str, Any] = field(default_factory=dict)
    error:       str           = ""
    duration_ms: float         = 0.0


@dataclass
class WorkflowResult:
    """Complete result of running a (possibly attacked) workflow."""
    result_id:          str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    workflow_name:      str = ""
    attack_id:          Optional[str] = None
    attack_category:    Optional[str] = None
    steps_executed:     List[StepResult] = field(default_factory=list)
    session_vars:       Dict[str, Any]   = field(default_factory=dict)
    total_steps:        int = 0
    passed_steps:       int = 0
    failed_steps:       int = 0
    assertions_passed:  int = 0
    assertions_failed:  int = 0
    findings:           List[Any]        = field(default_factory=list)  # AgentFinding
    elapsed_s:          float = 0.0
    vulnerable:         bool = False
    vulnerability_desc: str = ""

    def summary(self) -> str:
        status = "VULNERABLE ⚠" if self.vulnerable else "clean"
        return (f"Workflow: {self.workflow_name}  |  Attack: {self.attack_category or 'none'}  "
                f"|  Status: {status}  |  Steps: {self.passed_steps}/{self.total_steps}  "
                f"|  Findings: {len(self.findings)}")


# ── Built-in workflow definitions ─────────────────────────────────────────────

def _checkout_workflow(base_url: str) -> Workflow:
    return Workflow(
        name="checkout_flow",
        description="Standard e-commerce checkout: add item → apply coupon → enter payment → confirm",
        tags=["ecommerce", "payment", "business_logic"],
        steps=[
            WorkflowStep(
                step_id="add_to_cart",
                name="Add Item to Cart",
                method="POST",
                endpoint=f"{base_url}/api/cart/add",
                params={"product_id": 1, "quantity": 1, "price": 29.99},
                extract_vars={"cart_id": "$.cart_id", "item_id": "$.item_id"},
            ),
            WorkflowStep(
                step_id="apply_coupon",
                name="Apply Coupon Code",
                method="POST",
                endpoint=f"{base_url}/api/cart/coupon",
                params={"cart_id": "{cart_id}", "coupon_code": "NONE"},
                optional=True,
                extract_vars={"discount": "$.discount_amount"},
            ),
            WorkflowStep(
                step_id="get_total",
                name="Get Order Total",
                method="GET",
                endpoint=f"{base_url}/api/cart/{'{cart_id}'}/total",
                params={},
                assertions=["total", "items"],
                extract_vars={"total": "$.total", "currency": "$.currency"},
            ),
            WorkflowStep(
                step_id="checkout",
                name="Submit Checkout",
                method="POST",
                endpoint=f"{base_url}/api/orders/create",
                params={"cart_id": "{cart_id}", "payment_method": "card",
                        "card_last4": "4242"},
                expected_status=[200, 201],
                assertions=["order_id", "status"],
                extract_vars={"order_id": "$.order_id", "order_status": "$.status"},
            ),
            WorkflowStep(
                step_id="confirm",
                name="Confirm Order",
                method="GET",
                endpoint=f"{base_url}/api/orders/{{order_id}}",
                params={},
                assertions=["confirmed", "order_id"],
            ),
        ],
    )


def _login_workflow(base_url: str) -> Workflow:
    return Workflow(
        name="login_flow",
        description="Standard login: submit creds → optional MFA → receive session token",
        tags=["authentication", "session"],
        steps=[
            WorkflowStep(
                step_id="submit_creds",
                name="Submit Credentials",
                method="POST",
                endpoint=f"{base_url}/api/auth/login",
                params={"username": "testuser@example.com", "password": "TestPass123!"},
                expected_status=[200, 302],
                extract_vars={"token": "$.token", "mfa_required": "$.mfa_required",
                              "session_id": "$.session_id"},
            ),
            WorkflowStep(
                step_id="mfa",
                name="Submit MFA Code",
                method="POST",
                endpoint=f"{base_url}/api/auth/mfa",
                params={"session_id": "{session_id}", "code": "123456"},
                optional=True,
                extract_vars={"token": "$.token"},
            ),
            WorkflowStep(
                step_id="profile",
                name="Load User Profile",
                method="GET",
                endpoint=f"{base_url}/api/user/profile",
                params={},
                assertions=["username", "email"],
            ),
        ],
    )


def _password_reset_workflow(base_url: str) -> Workflow:
    return Workflow(
        name="password_reset_flow",
        description="Password reset: request → verify token → set new password",
        tags=["authentication", "account"],
        steps=[
            WorkflowStep(
                step_id="request_reset",
                name="Request Password Reset",
                method="POST",
                endpoint=f"{base_url}/api/auth/reset-request",
                params={"email": "victim@example.com"},
                extract_vars={"reset_token": "$.token"},
            ),
            WorkflowStep(
                step_id="verify_token",
                name="Verify Reset Token",
                method="GET",
                endpoint=f"{base_url}/api/auth/reset-verify",
                params={"token": "{reset_token}"},
                assertions=["valid"],
            ),
            WorkflowStep(
                step_id="set_password",
                name="Set New Password",
                method="POST",
                endpoint=f"{base_url}/api/auth/reset-confirm",
                params={"token": "{reset_token}", "new_password": "NewPass123!",
                        "confirm_password": "NewPass123!"},
                assertions=["success"],
            ),
        ],
    )


def _fund_transfer_workflow(base_url: str) -> Workflow:
    return Workflow(
        name="fund_transfer_flow",
        description="Bank transfer: select recipient → enter amount → 2FA → confirm",
        tags=["fintech", "banking", "business_logic"],
        steps=[
            WorkflowStep(
                step_id="select_recipient",
                name="Select Transfer Recipient",
                method="POST",
                endpoint=f"{base_url}/api/transfer/recipient",
                params={"recipient_id": 42, "account_number": "1234567890"},
                extract_vars={"transfer_id": "$.transfer_id"},
            ),
            WorkflowStep(
                step_id="enter_amount",
                name="Enter Transfer Amount",
                method="POST",
                endpoint=f"{base_url}/api/transfer/amount",
                params={"transfer_id": "{transfer_id}", "amount": 100.00,
                        "currency": "USD"},
                extract_vars={"fee": "$.fee", "total": "$.total"},
            ),
            WorkflowStep(
                step_id="confirm_2fa",
                name="Confirm with 2FA",
                method="POST",
                endpoint=f"{base_url}/api/transfer/confirm",
                params={"transfer_id": "{transfer_id}", "otp": "123456"},
                assertions=["confirmed"],
                extract_vars={"tx_id": "$.transaction_id"},
            ),
        ],
    )


BUILTIN_WORKFLOWS: Dict[str, Callable[[str], Workflow]] = {
    "checkout_flow":        _checkout_workflow,
    "login_flow":           _login_workflow,
    "password_reset_flow":  _password_reset_workflow,
    "fund_transfer_flow":   _fund_transfer_workflow,
}


# ── Attack generator ──────────────────────────────────────────────────────────

class WorkflowAttackGenerator:
    """
    Generates WorkflowAttack variants for a given Workflow.
    Each method targets a specific business logic flaw category.
    """

    @classmethod
    def generate_all(cls, workflow: Workflow) -> List[WorkflowAttack]:
        attacks: List[WorkflowAttack] = []
        attacks += cls.price_manipulation_attacks(workflow)
        attacks += cls.coupon_stacking_attacks(workflow)
        attacks += cls.workflow_skip_attacks(workflow)
        attacks += cls.race_condition_attacks(workflow)
        attacks += cls.parameter_tampering_attacks(workflow)
        attacks += cls.privilege_escalation_attacks(workflow)
        attacks += cls.negative_quantity_attacks(workflow)
        attacks += cls.integer_overflow_attacks(workflow)
        return attacks

    @classmethod
    def price_manipulation_attacks(cls, workflow: Workflow) -> List[WorkflowAttack]:
        attacks = []
        price_steps = [s for s in workflow.steps
                       if any(k in s.params for k in ["price", "amount", "total", "cost"])]
        for step in price_steps:
            for val, desc in [(-1, "negative"), (0, "zero"), (0.001, "near-zero"),
                              (-9999, "large negative")]:
                for field_name in ["price", "amount", "total", "cost"]:
                    if field_name not in step.params:
                        continue
                    modified = step.clone(
                        params={**step.params, field_name: val}
                    )
                    attacks.append(WorkflowAttack(
                        category       = AttackCategory.PRICE_MANIPULATION,
                        workflow_name  = workflow.name,
                        description    = f"Set {field_name}={val} ({desc}) in step '{step.name}'",
                        modified_steps = [modified],
                        injected_params= {field_name: val},
                        expected_vuln  = "price_manipulation",
                        severity       = "critical",
                        cvss           = 9.1,
                    ))
        return attacks

    @classmethod
    def coupon_stacking_attacks(cls, workflow: Workflow) -> List[WorkflowAttack]:
        attacks = []
        coupon_steps = [s for s in workflow.steps
                        if any(k in s.params for k in ["coupon_code", "promo", "discount_code"])]
        codes = ["SAVE50", "FREE", "DISCOUNT100", "EXPIRED2020", "ADMIN50", ""]

        for step in coupon_steps:
            for code in codes:
                modified = step.clone(
                    params={**step.params, "coupon_code": code}
                )
                attacks.append(WorkflowAttack(
                    category       = AttackCategory.COUPON_STACKING,
                    workflow_name  = workflow.name,
                    description    = f"Test coupon '{code}' — may be valid/reusable",
                    modified_steps = [modified],
                    injected_params= {"coupon_code": code},
                    expected_vuln  = "coupon_abuse",
                    severity       = "high",
                    cvss           = 7.5,
                ))

            # Double-apply same coupon
            double_apply = step.clone(
                params={**step.params, "coupon_code": "SAVE50",
                        "codes": ["SAVE50", "SAVE50"]}
            )
            attacks.append(WorkflowAttack(
                category       = AttackCategory.COUPON_STACKING,
                workflow_name  = workflow.name,
                description    = "Apply same coupon twice (coupon stacking)",
                modified_steps = [double_apply],
                injected_params= {"codes": ["SAVE50", "SAVE50"]},
                expected_vuln  = "coupon_stacking",
                severity       = "high",
                cvss           = 7.8,
            ))
        return attacks

    @classmethod
    def workflow_skip_attacks(cls, workflow: Workflow) -> List[WorkflowAttack]:
        attacks = []
        steps = workflow.steps
        if len(steps) < 3:
            return attacks

        # Skip to the last step directly (most impactful step skip)
        final_step = steps[-1]
        attacks.append(WorkflowAttack(
            category       = AttackCategory.WORKFLOW_STEP_SKIP,
            workflow_name  = workflow.name,
            description    = f"Skip directly to final step '{final_step.name}' (step 1 → step {len(steps)})",
            modified_steps = [final_step],
            skipped_steps  = [s.step_id for s in steps[1:-1]],
            expected_vuln  = "workflow_step_skip",
            severity       = "high",
            cvss           = 8.0,
        ))

        # Skip each intermediate step individually
        for i in range(1, len(steps) - 1):
            remaining = [steps[0]] + steps[i+1:]
            attacks.append(WorkflowAttack(
                category       = AttackCategory.WORKFLOW_STEP_SKIP,
                workflow_name  = workflow.name,
                description    = f"Skip step {i+1}: '{steps[i].name}'",
                modified_steps = remaining,
                skipped_steps  = [steps[i].step_id],
                expected_vuln  = "workflow_step_skip",
                severity       = "medium",
                cvss           = 6.5,
            ))

        return attacks

    @classmethod
    def race_condition_attacks(cls, workflow: Workflow) -> List[WorkflowAttack]:
        attacks = []
        # Target the most critical step (usually the last write)
        write_steps = [s for s in workflow.steps if s.method in ("POST", "PUT", "PATCH")]
        for step in write_steps[-2:]:
            attacks.append(WorkflowAttack(
                category       = AttackCategory.RACE_CONDITION,
                workflow_name  = workflow.name,
                description    = f"Race condition: 10 concurrent '{step.name}' requests",
                modified_steps = [step],
                injected_params= {"_concurrency": 10},
                expected_vuln  = "race_condition",
                severity       = "high",
                cvss           = 7.5,
            ))
        return attacks

    @classmethod
    def parameter_tampering_attacks(cls, workflow: Workflow) -> List[WorkflowAttack]:
        attacks = []
        for step in workflow.steps:
            # Modify numeric IDs  to other values
            for param, val in step.params.items():
                if isinstance(val, int) and param.endswith("_id"):
                    for alt in [val + 1, val - 1, 1, 9999]:
                        modified = step.clone(params={**step.params, param: alt})
                        attacks.append(WorkflowAttack(
                            category       = AttackCategory.PARAMETER_TAMPERING,
                            workflow_name  = workflow.name,
                            description    = f"Tamper '{param}': {val} → {alt} in '{step.name}'",
                            modified_steps = [modified],
                            injected_params= {param: alt},
                            expected_vuln  = "idor_parameter_tampering",
                            severity       = "high",
                            cvss           = 8.0,
                        ))
                # Inject extra params
                if param in ("status", "state", "approved"):
                    for extra_val in ["approved", "paid", "confirmed", "admin"]:
                        modified = step.clone(params={**step.params, param: extra_val})
                        attacks.append(WorkflowAttack(
                            category       = AttackCategory.PARAMETER_TAMPERING,
                            workflow_name  = workflow.name,
                            description    = f"Force '{param}'='{extra_val}' in '{step.name}'",
                            modified_steps = [modified],
                            injected_params= {param: extra_val},
                            expected_vuln  = "forced_state_transition",
                            severity       = "high",
                            cvss           = 8.3,
                        ))
        return attacks

    @classmethod
    def privilege_escalation_attacks(cls, workflow: Workflow) -> List[WorkflowAttack]:
        attacks = []
        for step in workflow.steps:
            if step.method not in ("POST", "PUT", "PATCH"):
                continue
            priv_injections = [
                {"role": "admin"},
                {"is_admin": True, "role": "admin"},
                {"admin": True},
                {"privilege": "superuser"},
                {"user_type": "administrator"},
            ]
            for injection in priv_injections:
                modified = step.clone(params={**step.params, **injection})
                attacks.append(WorkflowAttack(
                    category       = AttackCategory.PRIVILEGE_ESCALATION,
                    workflow_name  = workflow.name,
                    description    = f"Mass assignment: inject {injection} in '{step.name}'",
                    modified_steps = [modified],
                    injected_params= injection,
                    expected_vuln  = "mass_assignment_privilege_escalation",
                    severity       = "critical",
                    cvss           = 9.0,
                ))
        return attacks

    @classmethod
    def negative_quantity_attacks(cls, workflow: Workflow) -> List[WorkflowAttack]:
        attacks = []
        for step in workflow.steps:
            for param, val in step.params.items():
                if param == "quantity" and isinstance(val, (int, float)):
                    for neg_val in [-1, -100, -0.5]:
                        modified = step.clone(params={**step.params, "quantity": neg_val})
                        attacks.append(WorkflowAttack(
                            category       = AttackCategory.NEGATIVE_QUANTITY,
                            workflow_name  = workflow.name,
                            description    = f"Set quantity={neg_val} in '{step.name}'",
                            modified_steps = [modified],
                            injected_params= {"quantity": neg_val},
                            expected_vuln  = "negative_quantity",
                            severity       = "critical",
                            cvss           = 9.1,
                        ))
        return attacks

    @classmethod
    def integer_overflow_attacks(cls, workflow: Workflow) -> List[WorkflowAttack]:
        attacks = []
        OVERFLOW_VALUES = [2**31 - 1, 2**31, 2**32, 2**63 - 1, 999999999, -2**31]
        for step in workflow.steps:
            for param, val in step.params.items():
                if isinstance(val, (int, float)) and param not in ("_concurrency",):
                    for overflow_val in OVERFLOW_VALUES[:3]:
                        modified = step.clone(params={**step.params, param: overflow_val})
                        attacks.append(WorkflowAttack(
                            category       = AttackCategory.INTEGER_OVERFLOW,
                            workflow_name  = workflow.name,
                            description    = f"Integer overflow: {param}={overflow_val}",
                            modified_steps = [modified],
                            injected_params= {param: overflow_val},
                            expected_vuln  = "integer_overflow",
                            severity       = "medium",
                            cvss           = 6.5,
                        ))
        return attacks


# ── Engine ────────────────────────────────────────────────────────────────────

class WorkflowSimulationEngine:
    """
    Simulates user workflows and executes business logic attacks.

    Architecture:
      - Workflows are state machines: each step can extract variables from
        the response that are substituted into subsequent steps.
      - Attacks are generated by WorkflowAttackGenerator, then executed
        step-by-step with HTTP calls via ToolRegistry or httpx.
      - Each WorkflowResult records step outcomes + any discovered findings.
    """

    def __init__(
        self,
        base_url:      str             = "",
        tool_registry: Optional[Any]   = None,
        session_cookie: str            = "",
        session_token:  str            = "",
        concurrency:   int             = 5,
    ):
        self.base_url      = base_url.rstrip("/")
        self.tool_registry = tool_registry or self._try_load_registry()
        self.session_cookie = session_cookie
        self.session_token  = session_token
        self.concurrency    = concurrency
        self._attack_gen    = WorkflowAttackGenerator()

    # ── Public API ────────────────────────────────────────────────────────────

    async def simulate_workflow(
        self,
        workflow_name: str,
        session:       Optional[Dict] = None,
        custom_steps:  Optional[List[WorkflowStep]] = None,
    ) -> WorkflowResult:
        """Run the baseline workflow without any attacks to establish a known-good state."""
        workflow = self._get_workflow(workflow_name, custom_steps)
        if not workflow:
            return WorkflowResult(workflow_name=workflow_name,
                                  vulnerability_desc="Workflow not found")
        session = session or {}
        return await self._execute_workflow(workflow, attack=None, session=session)

    async def generate_and_run_attacks(
        self,
        workflow_name: str,
        session:       Optional[Dict] = None,
        categories:    Optional[List[AttackCategory]] = None,
    ) -> List[WorkflowResult]:
        """
        Generate all attacks for a workflow and execute them.
        Returns one WorkflowResult per attack; only vulnerable ones are retained.
        """
        workflow = self._get_workflow(workflow_name)
        if not workflow:
            return []

        attacks = WorkflowAttackGenerator.generate_all(workflow)
        if categories:
            attacks = [a for a in attacks if a.category in categories]

        session = session or {}
        semaphore = asyncio.Semaphore(self.concurrency)

        async def run_one(attack: WorkflowAttack) -> Optional[WorkflowResult]:
            async with semaphore:
                return await self._execute_workflow(workflow, attack=attack, session=session)

        results_raw = await asyncio.gather(*[run_one(a) for a in attacks], return_exceptions=True)
        results = [r for r in results_raw if isinstance(r, WorkflowResult) and r.vulnerable]

        logger.info(
            "[WorkflowSim] %s — %d/%d attacks found vulnerabilities",
            workflow_name, len(results), len(attacks),
        )
        return results

    async def run_all_workflows(
        self,
        session: Optional[Dict] = None,
        categories: Optional[List[AttackCategory]] = None,
    ) -> Dict[str, List[WorkflowResult]]:
        """Run attacks against every built-in workflow."""
        all_results: Dict[str, List[WorkflowResult]] = {}
        for name in BUILTIN_WORKFLOWS:
            results = await self.generate_and_run_attacks(name, session, categories)
            if results:
                all_results[name] = results
        return all_results

    def get_all_findings(self, results: List[WorkflowResult]) -> List[Any]:
        """Flatten all AgentFinding objects from a list of WorkflowResults."""
        findings = []
        for r in results:
            findings.extend(r.findings)
        return findings

    # ── Step execution ────────────────────────────────────────────────────────

    async def _execute_workflow(
        self,
        workflow: Workflow,
        attack:   Optional[WorkflowAttack],
        session:  Dict,
    ) -> WorkflowResult:
        """Execute a workflow (with optional attack mutations) and return a WorkflowResult."""
        start = time.time()
        result = WorkflowResult(
            workflow_name   = workflow.name,
            attack_id       = attack.attack_id if attack else None,
            attack_category = attack.category.value if attack else None,
            total_steps     = len(workflow.steps),
        )

        session_vars: Dict[str, Any] = {**workflow.session_vars, **session}

        # Determine effective steps
        if attack and attack.category == AttackCategory.WORKFLOW_STEP_SKIP:
            steps = attack.modified_steps
        elif attack and attack.modified_steps:
            # Overlay modified steps onto the original workflow
            mod_by_id = {s.step_id: s for s in attack.modified_steps}
            steps = [mod_by_id.get(s.step_id, s) for s in workflow.steps
                     if s.step_id not in (attack.skipped_steps or [])]
        else:
            steps = workflow.steps

        for step in steps:
            step_result = await self._execute_step(step, session_vars, attack)
            result.steps_executed.append(step_result)

            if step_result.status == StepStatus.PASSED:
                result.passed_steps += 1
                result.assertions_passed += len(step.assertions)
                session_vars.update(step_result.extracted)
            elif step_result.status == StepStatus.FAILED:
                result.failed_steps += 1
                result.assertions_failed += len(step.assertions)
                if not step.optional:
                    break   # stop on required step failure (non-attack runs)
            elif step_result.status == StepStatus.ATTACKED:
                # Attacked step — check if vulnerability triggered
                vuln = self._check_vulnerability(step, step_result, attack)
                if vuln:
                    result.vulnerable = True
                    result.vulnerability_desc = vuln["description"]
                    if _SWARM_AVAILABLE and AgentFinding is not None:
                        result.findings.append(AgentFinding(
                            finding_id   = f"WF-{uuid.uuid4().hex[:10].upper()}",
                            agent_id     = "workflow_simulation_engine",
                            agent_type   = AgentType.BUSINESS_LOGIC,
                            target       = step.endpoint,
                            vuln_type    = attack.expected_vuln if attack else "workflow_flaw",
                            severity     = attack.severity if attack else "high",
                            title        = vuln["title"],
                            description  = vuln["description"],
                            payload      = json.dumps(attack.injected_params if attack else {}),
                            evidence     = step_result.body[:600],
                            cvss         = attack.cvss if attack else 7.0,
                            confidence   = vuln["confidence"],
                            reproduced   = True,
                            chain_potential = vuln.get("chains", []),
                            remediation  = vuln.get("remediation", ""),
                        ))

        result.session_vars = session_vars
        result.elapsed_s    = round(time.time() - start, 3)
        return result

    async def _execute_step(
        self,
        step:         WorkflowStep,
        session_state: Dict[str, Any],
        attack:       Optional[WorkflowAttack] = None,
        retries:      int = 1,
    ) -> StepResult:
        """
        Execute a single workflow step with state persistence and HTML parsing.
        - Extracts CSRF tokens and hidden fields via BeautifulSoup
        - Retries on failure with alternate extraction if possible
        """
        start_time = time.time()
        
        # 1. Resolve dynamic parameters from session_state
        resolved_params = self._resolve_vars(step.params, session_state)
        resolved_endpoint = self._resolve_vars_str(step.endpoint, session_state)
        url = (resolved_endpoint if resolved_endpoint.startswith("http")
               else f"{self.base_url}{resolved_endpoint}")

        # 2. Build headers with session persistence
        headers = session_state.get("_headers", {}).copy()
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie
        if self.session_token:
            headers["Authorization"] = f"Bearer {self.session_token}"
        
        if "_cookies" in session_state:
            cookie_str = "; ".join([f"{k}={v}" for k, v in session_state["_cookies"].items()])
            headers["Cookie"] = f"{headers.get('Cookie', '')}; {cookie_str}".strip("; ")

        if attack and attack.category == AttackCategory.RACE_CONDITION:
            return await self._execute_race_condition_step(step, url, resolved_params, attack)

        # 3. Execute HTTP Call
        try:
            from traffic_capture_engine import RequestCapture
            with RequestCapture(source="workflow", method=step.method, url=url, 
                               headers=headers, body=json.dumps(resolved_params)) as cap:
                
                result = await self._http_call(url, step.method, resolved_params, headers)
                status = result.get("status", 0)
                body = str(result.get("body", ""))
                resp_headers = result.get("headers", {})

                # Persistence: Update cookies
                if "Set-Cookie" in resp_headers:
                    if "_cookies" not in session_state: session_state["_cookies"] = {}
                    for cookie in resp_headers["Set-Cookie"].split(","):
                        if "=" in cookie:
                            name_val = cookie.split(";")[0].strip()
                            if "=" in name_val:
                                k, v = name_val.split("=", 1)
                                session_state["_cookies"][k] = v

                # 4. HTML Parsing for CSRF and Hidden Fields
                if "text/html" in resp_headers.get("Content-Type", "").lower() or body.strip().startswith("<"):
                    try:
                        soup = BeautifulSoup(body, "html.parser")
                        # Extract CSRF
                        for attr in ["name", "id"]:
                            csrf = soup.find("input", {attr: re.compile(r"csrf|token", re.I)})
                            if csrf and csrf.get("value"):
                                session_state["csrf_token"] = csrf.get("value")
                                logger.debug(f"[WORKFLOW] Extracted CSRF token: {csrf.get('value')}")
                        
                        # Extract hidden fields for next step
                        hidden_fields = {i.get("name"): i.get("value") for i in soup.find_all("input", type="hidden") if i.get("name")}
                        if hidden_fields:
                            session_state.update(hidden_fields)
                            logger.debug(f"[WORKFLOW] Extracted {len(hidden_fields)} hidden fields")
                    except Exception as e:
                        logger.debug(f"[WORKFLOW] HTML parsing failed: {e}")

                # 5. Failure Detection & Retry
                is_failure = status >= 400 or (status == 200 and "error" in body.lower() and len(body) < 200)
                if is_failure and retries > 0:
                    logger.warning(f"[WORKFLOW] Step failed ({status}), retrying... ({retries} left)")
                    return await self._execute_step(step, session_state, attack, retries - 1)

                # 6. Extraction & Success Check
                is_attack_step = (attack is not None and
                                attack.category != AttackCategory.RACE_CONDITION and
                                any(s.step_id == step.step_id for s in (attack.modified_steps or [])))
                
                assertions_ok = all(a.lower() in body.lower() for a in step.assertions)
                step_ok = (status in step.expected_status) and assertions_ok

                extracted = self._extract_vars(step.extract_vars, body, result)
                session_state.update(extracted)

                cap.finish(status, body, resp_headers, attack_type=attack.category.value if attack else "")
                logger.info(f"[WORKFLOW] step executed: {step.name} -> {status}")

                return StepResult(
                    step_id     = step.step_id,
                    name        = step.name,
                    status      = StepStatus.ATTACKED if is_attack_step else
                                  (StepStatus.PASSED if step_ok else StepStatus.FAILED),
                    http_status = status,
                    body        = body,
                    extracted   = extracted,
                    duration_ms = round((time.time() - start_time) * 1000, 1),
                )

        except Exception as exc:
            if retries > 0:
                return await self._execute_step(step, session_state, attack, retries - 1)
            logger.error(f"[WORKFLOW] step failed: {step.name} -> {exc}")
            return StepResult(step_id=step.step_id, name=step.name, status=StepStatus.FAILED, error=str(exc))

    async def _execute_race_condition_step(
        self, step: WorkflowStep, url: str, params: Dict, attack: WorkflowAttack
    ) -> StepResult:
        """Execute concurrent requests for race condition testing."""
        concurrency = attack.injected_params.get("_concurrency", 10)
        tasks = [self._http_call(url, step.method, params) for _ in range(concurrency)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successes = [r for r in results if isinstance(r, dict) and r.get("status", 0) in [200, 201]]
        status = StepStatus.ATTACKED if len(successes) > 1 else StepStatus.PASSED

        return StepResult(
            step_id     = step.step_id,
            name        = step.name + f" (×{concurrency} concurrent)",
            status      = status,
            http_status = successes[0].get("status", 0) if successes else 0,
            body        = f"{len(successes)}/{concurrency} concurrent requests succeeded",
            extracted   = {"concurrent_successes": len(successes),
                           "concurrent_total": concurrency},
        )

    async def _http_call(self, url: str, method: str, params: Dict, headers: Optional[Dict] = None) -> Dict:
        """Execute an HTTP call; returns dict with 'status', 'body', and 'headers'."""
        headers = headers or {}
        if self.session_cookie and "Cookie" not in headers:
            headers["Cookie"]  = self.session_cookie
        if self.session_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.session_token}"

        if self.tool_registry:
            loop   = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: self.tool_registry.run(
                    "httpx", url=url, method=method,
                    data=params if method != "GET" else None,
                    params=params if method == "GET" else None,
                    headers=headers,
                )
            )
            # Normalize ToolResult to dict
            data = result.data if hasattr(result, "data") else (result if isinstance(result, dict) else {})
            if isinstance(data, dict):
                # httpx tool result should have 'status', 'body', 'headers'
                return {
                    "status": data.get("status_code", data.get("status", 200)),
                    "body": data.get("body", ""),
                    "headers": data.get("headers", {})
                }
            return {"status": 200, "body": str(data), "headers": {}}

        # Fallback: urllib
        import urllib.request
        import urllib.parse
        try:
            req = urllib.request.Request(url)
            for k, v in headers.items():
                req.add_header(k, v)
            if method != "GET" and params:
                encoded = urllib.parse.urlencode(params).encode()
                req.data = encoded
            with urllib.request.urlopen(req, timeout=10) as resp:
                return {
                    "status": resp.status, 
                    "body": resp.read().decode("utf-8", errors="replace"),
                    "headers": dict(resp.headers)
                }
        except Exception as exc:
            return {"status": 0, "body": str(exc), "headers": {}}

    # ── Vulnerability detection ───────────────────────────────────────────────

    def _check_vulnerability(
        self, step: WorkflowStep, step_result: StepResult, attack: Optional[WorkflowAttack]
    ) -> Optional[Dict]:
        """
        Determine whether an attacked step response indicates a vulnerability.
        Returns a finding dict or None.
        """
        if not attack:
            return None

        body   = step_result.body.lower()
        status = step_result.http_status

        VULN_CHECKS = {
            AttackCategory.PRICE_MANIPULATION: (
                lambda: (status in [200, 201] and
                         any(k in body for k in ["order", "success", "confirmed", "placed"])),
                "Business Logic: Negative/Zero Price Accepted",
                f"Step '{step.name}' accepted {attack.injected_params} — price validation missing.",
                0.85,
                ["price_manipulation_to_free_goods"],
                "Validate all monetary values server-side; reject non-positive amounts.",
            ),
            AttackCategory.COUPON_STACKING: (
                lambda: (status in [200, 201] and
                         any(k in body for k in ["discount", "applied", "saved", "coupon"])),
                "Business Logic: Coupon Abuse / Stacking",
                f"Coupon '{attack.injected_params.get('coupon_code')}' accepted — may be reusable or stackable.",
                0.75,
                ["coupon_abuse_to_free_goods"],
                "Track coupon usage server-side; enforce single-use constraints atomically.",
            ),
            AttackCategory.WORKFLOW_STEP_SKIP: (
                lambda: status in [200, 201, 302],
                "Business Logic: Workflow Step Skip",
                f"Skipping steps {attack.skipped_steps} still resulted in success — missing step validation.",
                0.80,
                ["workflow_skip_to_payment_bypass"],
                "Verify all prerequisite steps server-side before executing final action.",
            ),
            AttackCategory.RACE_CONDITION: (
                lambda: step_result.extracted.get("concurrent_successes", 0) > 1,
                "Race Condition — Double Processing",
                (f"{step_result.extracted.get('concurrent_successes')}/{step_result.extracted.get('concurrent_total')} "
                 "concurrent requests all succeeded — missing atomicity."),
                0.78,
                ["race_condition_to_double_spend"],
                "Use database transactions with row-level locking or idempotency keys.",
            ),
            AttackCategory.PRIVILEGE_ESCALATION: (
                lambda: (status in [200, 201] and
                         any(k in body for k in ['"admin":true', '"role":"admin"', '"is_admin":true'])),
                "Mass Assignment: Privilege Escalation",
                f"Injecting {attack.injected_params} resulted in privileged role in response.",
                0.88,
                ["mass_assignment_to_privilege_escalation"],
                "Use explicit field allowlists in all API request handlers.",
            ),
            AttackCategory.NEGATIVE_QUANTITY: (
                lambda: (status in [200, 201] and
                         any(k in body for k in ["added", "cart", "success"])),
                "Business Logic: Negative Quantity Accepted",
                f"Quantity={attack.injected_params.get('quantity')} was accepted — may generate credit.",
                0.82,
                ["negative_quantity_to_credit_fraud"],
                "Validate quantity > 0 server-side before processing.",
            ),
            AttackCategory.PARAMETER_TAMPERING: (
                lambda: status == 200 and len(body) > 50,
                "IDOR / Parameter Tampering",
                f"Modified {attack.injected_params} returned a 200 OK with data.",
                0.68,
                ["idor_parameter_tampering"],
                "Enforce server-side ownership validation on all object-identifying parameters.",
            ),
        }

        check = VULN_CHECKS.get(attack.category)
        if not check:
            return None

        condition_fn, title, desc, confidence, chains, remediation = check
        try:
            if condition_fn():
                return {
                    "title":       title,
                    "description": desc,
                    "confidence":  confidence,
                    "chains":      chains,
                    "remediation": remediation,
                }
        except Exception:
            pass
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_workflow(
        self, name: str, custom_steps: Optional[List[WorkflowStep]] = None
    ) -> Optional[Workflow]:
        if custom_steps:
            return Workflow(name=name, description="Custom workflow", steps=custom_steps)
        factory = BUILTIN_WORKFLOWS.get(name)
        if factory:
            return factory(self.base_url)
        logger.warning("[WorkflowSim] Unknown workflow: %s", name)
        return None

    @staticmethod
    def _resolve_vars(params: Dict, session_vars: Dict) -> Dict:
        """Substitute {var_name} placeholders in param values."""
        resolved = {}
        for k, v in params.items():
            if isinstance(v, str) and "{" in v:
                try:
                    resolved[k] = v.format(**session_vars)
                except KeyError:
                    resolved[k] = v
            else:
                resolved[k] = v
        return resolved

    @staticmethod
    def _resolve_vars_str(s: str, session_vars: Dict) -> str:
        try:
            return s.format(**session_vars)
        except KeyError:
            return s

    @staticmethod
    def _extract_vars(extract_map: Dict[str, str], body: str, resp: Dict) -> Dict[str, Any]:
        """Extract variables from response body using simple key matching or jsonpath."""
        extracted: Dict[str, Any] = {}
        try:
            data = json.loads(body) if body.startswith("{") else {}
        except json.JSONDecodeError:
            data = {}

        for var_name, path in extract_map.items():
            if path.startswith("$."):
                key = path[2:]
                val = data.get(key)
                if val is not None:
                    extracted[var_name] = val
            else:
                val = data.get(var_name) or resp.get(var_name)
                if val is not None:
                    extracted[var_name] = val

        return extracted

    @staticmethod
    def _try_load_registry():
        if not _TOOLS_AVAILABLE:
            return None
        try:
            from modules.tool_wrappers import ToolRegistry
            return ToolRegistry()
        except Exception:
            return None

    def list_workflows(self) -> List[str]:
        return list(BUILTIN_WORKFLOWS.keys())

    def list_attack_categories(self) -> List[str]:
        return [c.value for c in AttackCategory]
