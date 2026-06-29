# src/oneinfinity/scan/ai_red_teamer/models.py
from dataclasses import dataclass, field
from typing import Dict, Any

@dataclass
class AttackGoal:
    target_url: str
    objective: str
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AttackResult:
    success: bool
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    raw_response: str = ""
    log: list[str] = field(default_factory=list)
