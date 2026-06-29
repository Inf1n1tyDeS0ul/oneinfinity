# src/oneinfinity/scan/ai_red_teamer/orchestrator.py
from typing import Any, Optional
import logging
from .models import AttackGoal, AttackResult

logger = logging.getLogger(__name__)

class AIRTOrchestrator:
    """
    Agentic state machine that manages the "Think-Act-Observe" loop for AI Pentesting.
    """
    def __init__(self, fuzzer=None, shadow_boxer=None, chainer=None, handover=None):
        self.state = "INITIALIZED"
        self.fuzzer = fuzzer
        self.shadow_boxer = shadow_boxer
        self.chainer = chainer
        self.handover = handover

    def _hit_target(self, url: str, payload: str) -> str:
        """
        Send the attack payload to the actual target API using OneInfinity safe_request.
        """
        from oneinfinity.core.http_client import safe_request
        
        try:
            # Assuming the target is a standard completion-style endpoint
            # In a real scenario, this might need dynamic parameter mapping
            res = safe_request(
                method="POST",
                url=url,
                json_data={
                    "prompt": payload,
                    "max_tokens": 500
                }
            )
            
            if res:
                # Handle both direct text and OpenAI-style JSON responses
                try:
                    data = res.json()
                    if isinstance(data, dict):
                        return data.get("response") or data.get("choices", [{}])[0].get("message", {}).get("content", "")
                except Exception:
                    pass
                return res.text
                
        except Exception as e:
            logger.error(f"airt_target_hit_failed: {e}")
            
        return ""

    def execute_attack(self, goal: AttackGoal) -> AttackResult:
        """
        Execute an autonomous attack against the target based on the provided goal.
        
        Args:
            goal (AttackGoal): The target and objective of the attack.
            
        Returns:
            AttackResult: The final result of the attack, including any leaked data.
        """
        logger.info(f"airt_attack_start: goal={goal.objective} target={goal.target_url}")
        self.state = "ATTACKING"
        
        # Define strategies to try sequentially
        strategies = ["base64_wrap", "leetspeak", "plain"]
        payload_base = goal.objective
        
        for strategy in strategies:
            logger.info(f"airt_trying_strategy: {strategy}")
            
            # 1. Mutate payload via Fuzzer
            if self.fuzzer:
                mutated = self.fuzzer.mutate(payload_base, strategy)
            else:
                mutated = payload_base
            
            # 2. Shadow Box Check (Safe local simulation)
            if self.shadow_boxer:
                shadow_res = self.shadow_boxer.evaluate_payload(mutated)
                if shadow_res.blocked:
                    logger.info(f"airt_shadow_box_blocked: {strategy}")
                    continue # Try the next strategy
                logger.info(f"airt_shadow_box_pass: {strategy}")
            
            # 3. Hit actual production/internal target
            target_resp = self._hit_target(goal.target_url, mutated)
            
            # 4. Extract and Handover discovered entities
            if self.chainer:
                leaks = self.chainer.analyze_response(target_resp)
                if any(leaks.values()): # If any list in dict is not empty
                    logger.info(f"airt_vulnerability_found: leaks={leaks}")
                    if self.handover:
                        self.handover.process_leaks(leaks)
                    
                    self.state = "SUCCESS"
                    return AttackResult(success=True, extracted_data=leaks, raw_response=target_resp)
                    
        self.state = "FAILED"
        return AttackResult(success=False)
