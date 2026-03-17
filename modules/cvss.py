"""CVSS 3.1 calculator with interactive scoring and vector generation."""

from modules.utils import banner, section, ok, info, warn, bold, sev, ask

# ── CVSS 3.1 metric definitions ───────────────────────────────────────────────

METRICS = {
    "AV": {
        "label": "Attack Vector",
        "options": {
            "N": ("Network",          0.85, "Exploitable remotely over the internet"),
            "A": ("Adjacent",         0.62, "Requires access to local network / Bluetooth"),
            "L": ("Local",            0.55, "Requires local access to system"),
            "P": ("Physical",         0.20, "Requires physical access to device"),
        },
    },
    "AC": {
        "label": "Attack Complexity",
        "options": {
            "L": ("Low",  0.77, "No special conditions required"),
            "H": ("High", 0.44, "Requires specific conditions (race condition, config, etc.)"),
        },
    },
    "PR": {
        "label": "Privileges Required",
        "options": {
            "N": ("None",     0.85, "No authentication required"),
            "L": ("Low",      0.62, "Regular user privileges"),
            "H": ("High",     0.27, "Admin/root privileges"),
        },
    },
    "UI": {
        "label": "User Interaction",
        "options": {
            "N": ("None",     0.85, "No user interaction required"),
            "R": ("Required", 0.62, "Victim must click link, view page, etc."),
        },
    },
    "S": {
        "label": "Scope",
        "options": {
            "U": ("Unchanged", None, "Impact limited to the vulnerable component"),
            "C": ("Changed",   None, "Impact extends to other components"),
        },
    },
    "C": {
        "label": "Confidentiality Impact",
        "options": {
            "N": ("None", 0.00, "No impact on confidentiality"),
            "L": ("Low",  0.22, "Limited access to sensitive data"),
            "H": ("High", 0.56, "Full disclosure of data"),
        },
    },
    "I": {
        "label": "Integrity Impact",
        "options": {
            "N": ("None", 0.00, "No impact on integrity"),
            "L": ("Low",  0.22, "Partial modification of data"),
            "H": ("High", 0.56, "Complete loss of integrity / full modification"),
        },
    },
    "A": {
        "label": "Availability Impact",
        "options": {
            "N": ("None", 0.00, "No impact on availability"),
            "L": ("Low",  0.22, "Reduced performance or availability"),
            "H": ("High", 0.56, "Complete unavailability"),
        },
    },
}

ISS_WEIGHTS = {"N": 0.00, "L": 0.22, "H": 0.56}


def _iss(C: str, I: str, A: str) -> float:
    c = ISS_WEIGHTS[C]
    i = ISS_WEIGHTS[I]
    a = ISS_WEIGHTS[A]
    return 1 - (1 - c) * (1 - i) * (1 - a)


def calculate(vector: dict) -> tuple[float, str]:
    """Calculate CVSS 3.1 base score from a dict of metric values.

    Returns (score, severity_label).
    """
    AV = METRICS["AV"]["options"][vector["AV"]][1]
    AC = METRICS["AC"]["options"][vector["AC"]][1]
    PR_val = vector["PR"]
    UI = METRICS["UI"]["options"][vector["UI"]][1]
    S  = vector["S"]

    # PR score depends on scope
    PR_scores = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }
    PR = PR_scores[S][PR_val]

    C_val, I_val, A_val = vector["C"], vector["I"], vector["A"]
    iss = _iss(C_val, I_val, A_val)

    if iss == 0:
        return 0.0, "None"

    if S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * AV * AC * PR * UI

    if impact <= 0:
        base = 0.0
    elif S == "U":
        base = min(impact + exploitability, 10)
    else:
        base = min(1.08 * (impact + exploitability), 10)

    # Round up to 1 decimal
    import math
    base = math.ceil(base * 10) / 10

    if base == 0.0:
        label = "None"
    elif base < 4.0:
        label = "Low"
    elif base < 7.0:
        label = "Medium"
    elif base < 9.0:
        label = "High"
    else:
        label = "Critical"

    return round(base, 1), label


def vector_string(vector: dict) -> str:
    return (f"CVSS:3.1/AV:{vector['AV']}/AC:{vector['AC']}/PR:{vector['PR']}/"
            f"UI:{vector['UI']}/S:{vector['S']}/C:{vector['C']}/I:{vector['I']}/A:{vector['A']}")


def parse_vector(vec_str: str) -> dict | None:
    """Parse a CVSS:3.1/... string into a dict."""
    import re
    if not vec_str.startswith("CVSS:3.1/"):
        return None
    parts = vec_str.replace("CVSS:3.1/", "").split("/")
    result = {}
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            result[k] = v
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    if all(k in result for k in required):
        return result
    return None


class CVSSCalculator:
    def interactive(self) -> tuple[float, str, str] | None:
        """Walk the user through CVSS scoring interactively."""
        banner("CVSS 3.1 Calculator")
        vector = {}
        metric_order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

        for metric_key in metric_order:
            meta = METRICS[metric_key]
            section(f"{metric_key} — {meta['label']}")
            opts = meta["options"]
            for code, (name, _, desc) in opts.items():
                print(f"  {bold(code)}) {name:<15} — {desc}")
            while True:
                choice = ask(f"Select [{'/'.join(opts.keys())}]: ").strip().upper()
                if choice in opts:
                    vector[metric_key] = choice
                    print(f"  → {opts[choice][0]}")
                    break
                print(f"  Invalid choice. Options: {', '.join(opts.keys())}")

        score, label = calculate(vector)
        vec_str = vector_string(vector)

        print()
        banner("CVSS Result")
        print(f"  {bold('Score:')}    {sev(label.lower(), str(score))} / 10.0")
        print(f"  {bold('Severity:')} {sev(label.lower(), label)}")
        print(f"  {bold('Vector:')}   {vec_str}")
        print()

        return score, label, vec_str

    def from_vector(self, vec_str: str) -> tuple[float, str] | None:
        """Calculate from an existing vector string."""
        vector = parse_vector(vec_str)
        if not vector:
            warn(f"Invalid CVSS vector: {vec_str}")
            return None
        score, label = calculate(vector)
        print(f"  Score: {sev(label.lower(), str(score))} ({label})")
        print(f"  Vector: {vec_str}")
        return score, label

    def from_description(self, description: str) -> None:
        """Suggest likely CVSS values based on vuln description keywords."""
        desc = description.lower()
        banner("CVSS Suggestion (from description)")
        warn("This is a rough estimate — always verify each metric manually.")
        print()

        # Heuristic suggestions
        suggestions = {}

        # Attack Vector
        if any(k in desc for k in ["remote", "unauthenticated", "internet", "network"]):
            suggestions["AV"] = ("N", "Network — remotely exploitable")
        elif any(k in desc for k in ["adjacent", "local network", "wifi", "bluetooth"]):
            suggestions["AV"] = ("A", "Adjacent")
        elif any(k in desc for k in ["local", "file", "binary"]):
            suggestions["AV"] = ("L", "Local")
        else:
            suggestions["AV"] = ("N", "Network (assumed)")

        # Attack Complexity
        if any(k in desc for k in ["race condition", "timing", "complex", "specific config"]):
            suggestions["AC"] = ("H", "High — requires specific conditions")
        else:
            suggestions["AC"] = ("L", "Low — no special conditions needed")

        # Privileges Required
        if any(k in desc for k in ["unauthenticated", "no auth", "anonymous", "without login"]):
            suggestions["PR"] = ("N", "None — no authentication")
        elif any(k in desc for k in ["admin", "root", "administrator", "privileged"]):
            suggestions["PR"] = ("H", "High — admin required")
        else:
            suggestions["PR"] = ("L", "Low — regular user")

        # User Interaction
        if any(k in desc for k in ["click", "visit", "open", "user interaction", "phish"]):
            suggestions["UI"] = ("R", "Required — victim must interact")
        else:
            suggestions["UI"] = ("N", "None")

        # Scope
        if any(k in desc for k in ["other user", "cross-origin", "account takeover",
                                    "steal", "server-side", "rce", "execute"]):
            suggestions["S"] = ("C", "Changed — impacts beyond vulnerable component")
        else:
            suggestions["S"] = ("U", "Unchanged")

        # CIA
        if any(k in desc for k in ["read all", "full data", "database dump", "credentials",
                                    "pii", "sensitive data", "secrets"]):
            suggestions["C"] = ("H", "High confidentiality impact")
        elif any(k in desc for k in ["partial", "limited", "some data"]):
            suggestions["C"] = ("L", "Low")
        else:
            suggestions["C"] = ("N", "None")

        if any(k in desc for k in ["write", "modify", "delete", "overwrite", "rce", "execute"]):
            suggestions["I"] = ("H", "High integrity impact")
        elif "partial" in desc:
            suggestions["I"] = ("L", "Low")
        else:
            suggestions["I"] = ("N", "None")

        if any(k in desc for k in ["dos", "denial", "crash", "unavailable", "flood"]):
            suggestions["A"] = ("H", "High availability impact")
        else:
            suggestions["A"] = ("N", "None")

        for k, (code, reason) in suggestions.items():
            print(f"  {bold(METRICS[k]['label']):<25} {bold(code)} — {reason}")

        # Calculate
        vector = {k: v[0] for k, v in suggestions.items()}
        score, label = calculate(vector)
        vec_str = vector_string(vector)

        print()
        print(f"  {bold('Suggested Score:')} {sev(label.lower(), str(score))} ({label})")
        print(f"  {bold('Suggested Vector:')} {vec_str}")
        print()
        warn("Use 'oneinfinity cvss' for precise interactive scoring.")
