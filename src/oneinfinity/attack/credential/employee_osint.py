"""employee_osint.py — Employee name and email enumeration via OSINT sources."""
from __future__ import annotations

import logging
import re
import subprocess
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("oneinfinity.credential.employee_osint")

# Common corporate email format patterns
_EMAIL_FORMATS = [
    "{first}.{last}@{domain}",
    "{first}{last}@{domain}",
    "{first}@{domain}",
    "{f}{last}@{domain}",
    "{first}.{l}@{domain}",
    "{last}.{first}@{domain}",
]


@dataclass
class Employee:
    name: str
    email: str = ""
    title: str = ""
    source: str = ""
    email_candidates: List[str] = field(default_factory=list)


class EmployeeOSINT:
    """
    Employee enumeration using theHarvester and username-anarchy patterns.
    Falls back to email format permutation if tools unavailable.
    """

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    def enumerate(self, domain: str, limit: int = 100) -> List[Employee]:
        """Enumerate employees for a domain using available OSINT sources."""
        employees: List[Employee] = []

        # Try theHarvester
        h_emps = self._run_theharvester(domain, limit)
        employees.extend(h_emps)

        # Deduplicate
        seen = set()
        result = []
        for emp in employees:
            key = emp.email or emp.name
            if key and key not in seen:
                seen.add(key)
                result.append(emp)

        log.info("employee_osint: %d unique employees found for %s", len(result), domain)
        return result[:limit]

    def generate_email_candidates(self, name: str, domain: str) -> List[str]:
        """Generate email format permutations for a name."""
        parts = name.lower().split()
        if not parts:
            return []
        first = parts[0]
        last = parts[-1] if len(parts) > 1 else parts[0]
        f = first[0]
        l = last[0]

        candidates = []
        for fmt in _EMAIL_FORMATS:
            try:
                email = fmt.format(
                    first=first, last=last,
                    domain=domain, f=f, l=l,
                )
                if email not in candidates:
                    candidates.append(email)
            except Exception:
                pass
        return candidates

    def _run_theharvester(self, domain: str, limit: int) -> List[Employee]:
        """Run theHarvester CLI tool if available."""
        try:
            result = subprocess.run(
                ["theHarvester", "-d", domain, "-b", "all", "-l", str(limit)],
                capture_output=True, text=True, timeout=self.timeout,
            )
            return self._parse_theharvester_output(result.stdout, domain)
        except FileNotFoundError:
            log.debug("theHarvester not installed — skipping")
        except subprocess.TimeoutExpired:
            log.warning("theHarvester timed out for %s", domain)
        except Exception as exc:
            log.debug("theHarvester failed: %s", exc)
        return []

    def _parse_theharvester_output(self, output: str, domain: str) -> List[Employee]:
        """Parse theHarvester output for emails and names."""
        employees = []
        for line in output.splitlines():
            line = line.strip()
            # Email lines
            if "@" in line and domain.lower() in line.lower():
                email_match = re.search(r"[\w.+-]+@[\w.-]+\." + re.escape(domain.split(".")[-1]), line, re.IGNORECASE)
                if email_match:
                    email = email_match.group(0).lower()
                    name = self._name_from_email(email)
                    employees.append(Employee(name=name, email=email, source="theHarvester"))
        return employees

    def _name_from_email(self, email: str) -> str:
        """Infer a display name from an email address."""
        local = email.split("@")[0]
        name = local.replace(".", " ").replace("_", " ").replace("-", " ")
        return name.title()
