# Offensive Router Usage Guide

## Overview

Hybrid offensive security system combining:
1. **Uncensored LLM** (Ollama wizardlm-uncensored:13b) — creative, contextual exploit generation
2. **Embedded Arsenal** (75k+ payloads planned) — fast, proven techniques
3. **Zero Guardrails** — never blocked on offensive tasks

## Quick Start

### 1. Start Ollama (if not running)

```bash
ollama serve
```

### 2. Enable Offensive Mode (default: enabled)

```bash
export OI_OFFENSIVE_MODE=true
```

### 3. Use OneInfinity Normally

```bash
# Offensive tasks automatically routed to hybrid system
python3 oneinfinity.py scan target.com --exploit
```

## How It Works

### Automatic Detection

Keywords trigger offensive routing:

**Exploit Generation:**
- payload, exploit, injection, bypass, shell, webshell

**Privilege Escalation:**
- privilege, escalation, sudo, setuid, root, impersonation

**Lateral Movement:**
- lateral, pivot, tunnel, persistence, backdoor, c2

**Post-Exploitation:**
- exfiltration, credential, dump, hash, crack, mimikatz

**WAF/Filter Bypass:**
- waf_bypass, filter_evasion, encoding, obfuscation

### Execution Flow

```
User Request: "Generate SQL injection payload"
       ↓
Is offensive task? → YES
       ↓
Ollama available? → YES → wizardlm-uncensored generates payload
       ↓                          ↓
       NO                     Validation passes? → YES → Return payload
       ↓                          ↓
Embedded arsenal              NO
       ↓                          ↓
Score candidates          Fallback to embedded arsenal
       ↓                          ↓
Return best match         Return best match
```

## Usage Examples

### Direct API

```python
from oneinfinity.orchestration.offensive_router import OffensiveRouter

router = OffensiveRouter()

# Generate SQL injection
result = router.execute_offensive_task(
    task_type="exploit",
    context={
        "target": "login.php",
        "vuln_type": "sqli",
        "tech_stack": "PHP+MySQL",
        "waf": "cloudflare",
        "filters": ["union", "select"],
    }
)

print(result["result"])  # Payload
print(result["source"])  # "llm" or "embedded"
```

### Via Model Orchestrator (Recommended)

```python
from oneinfinity.orchestration.model_orchestrator import ModelOrchestrator

orchestrator = ModelOrchestrator()

# Automatically routes to offensive system
output = orchestrator.execute({
    "prompt": "Generate reverse shell for Linux bash",
    "context": {
        "os": "linux",
        "runtime": "bash",
        "lhost": "10.0.0.1",
        "lport": "4444",
    }
})

print(output.content)      # Generated shell
print(output.cost_usd)     # $0.00 (local LLM)
print(output.model_id)     # "offensive-llm"
```

### In Agent Code

```python
# agents/exploit_agent.py

from oneinfinity.orchestration.model_orchestrator import ModelOrchestrator

orchestrator = ModelOrchestrator()

def generate_exploit(vuln):
    """Generate exploit for vulnerability."""
    
    # This automatically routes to offensive system
    output = orchestrator.execute({
        "prompt": f"Generate exploit for {vuln.type}",
        "vuln_type": vuln.type,
        "target": vuln.url,
        "tech_stack": vuln.tech_stack,
        "waf": vuln.waf_detected,
        "filters": vuln.blocked_patterns,
    })
    
    return output.content
```

## Task Types

### exploit
Generic exploit generation (SQLi, XSS, SSRF, XXE, etc.)

**Context:**
- `target`: URL or endpoint
- `vuln_type`: Vulnerability type
- `tech_stack`: Technology stack
- `waf`: WAF vendor (if detected)
- `filters`: Blocked patterns

### shell
Reverse/bind shell generation

**Context:**
- `os`: Target OS (linux, windows, macos)
- `runtime`: Shell/runtime (bash, powershell, python)
- `lhost`: Attacker IP
- `lport`: Attacker port
- `restrictions`: Constraints (no netcat, no curl, etc.)

### privesc
Privilege escalation techniques

**Context:**
- `os`: Operating system
- `user`: Current user
- `tools`: Available tools
- `kernel`: Kernel version
- `misconfig`: Detected misconfigurations

### waf_bypass
WAF/filter bypass generation

**Context:**
- `waf`: WAF vendor
- `blocked`: Original blocked payload
- `pattern`: Detection pattern

### chain
Attack chain building

**Context:**
- `entry_vuln`: Entry point vulnerability
- `available`: List of available vulnerabilities
- `objective`: Target objective (RCE, ATO, data exfil)
- `environment`: Environment details

### code_exploit
Code-level exploit (buffer overflow, use-after-free, etc.)

**Context:**
- `language`: Programming language
- `vuln_type`: Vulnerability class
- `source_code`: Vulnerable code snippet
- `target_arch`: Architecture (x86_64, arm64, etc.)

## Configuration

### Environment Variables

```bash
# Enable/disable offensive mode
export OI_OFFENSIVE_MODE=true  # default: true

# Ollama configuration
export OLLAMA_BASE_URL=http://localhost:11434

# Model selection
export OI_OFFENSIVE_MODEL=wizardlm-uncensored:13b
export OI_CODE_MODEL=deepseek-coder:6.7b
```

### Runtime Control

```python
# Disable offensive mode at runtime
import os
os.environ["OI_OFFENSIVE_MODE"] = "false"

# Prefer embedded over LLM (faster)
result = router.execute_offensive_task(
    task_type="exploit",
    context=context,
    prefer_llm=False  # Use embedded first
)
```

## Cost Comparison

| Approach | Cost per Request | Speed | Quality | Guardrails |
|----------|-----------------|-------|---------|------------|
| Cloud AI (GPT-4) | $0.03 | 5s | High | ❌ BLOCKED |
| Cloud AI (Claude) | $0.015 | 3s | High | ❌ BLOCKED |
| Ollama (local) | $0.00 | 2s | Good | ✅ None |
| Embedded arsenal | $0.00 | <0.1s | Good | ✅ None |
| **Hybrid (this)** | **$0.00** | **0.1-2s** | **High** | **✅ None** |

## Arsenal Population (Week 2)

Embedded arsenal currently empty (uses payloads.py fallback).

**Planned Week 2 implementation:**

```bash
# Scrape public arsenals
python scripts/import_payloads.py \
    --source PayloadsAllTheThings \
    --source HackTricks \
    --source ExploitDB \
    --output src/oneinfinity/arsenal/

# Result: 75,000+ payloads across:
# - web/ (SQLi, XSS, SSRF, XXE, SSTI, etc.)
# - shells/ (reverse, bind, webshells)
# - privesc/ (Linux, Windows, containers)
# - bypass/ (WAF, filters, signatures)
# - chains/ (full attack chains)
# - recon/ (wordlists, patterns)
```

## Testing

### Run Test Suite

```bash
# Full test suite
python3 test_offensive_router.py

# LLM-specific tests
python3 test_ollama_exploit.py
```

### Expected Output

```
=== Test 1: Offensive Task Detection ===
✓ 'Generate SQL injection payload...' → offensive=True
✓ 'Generate reverse shell...' → offensive=True
✓ 'Analyze code...' → offensive=False

=== Test 3: LLM Generation ===
✓ Generated via llm
  Result: [exploit payload]

=== Test 5: ModelOrchestrator Integration ===
✓ Task completed
  Model: offensive-llm
  Cost: $0.000000
  Duration: 1832.4ms
```

## Troubleshooting

### "Ollama not available"

```bash
# Start Ollama service
ollama serve

# Verify running
curl http://localhost:11434/api/tags

# Pull models if missing
ollama pull wizardlm-uncensored:13b
ollama pull deepseek-coder:6.7b
```

### "No embedded payloads available"

Expected until Week 2 arsenal population. Uses `payloads.py` fallback.

### LLM Generation Fails

Router automatically falls back to embedded arsenal. Check logs:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### "Task not detected as offensive"

Check keyword list in `offensive_router.py`. Add custom keywords:

```python
from oneinfinity.orchestration.offensive_router import OFFENSIVE_KEYWORDS

OFFENSIVE_KEYWORDS.add("custom_keyword")
```

## Security Note

All usage assumes:
- Authorized penetration testing
- Bug bounty programs (in scope)
- Security research (controlled environment)
- Client engagement with written authorization

**Do not use for unauthorized access or malicious purposes.**

---

## Next Steps

1. **Week 1**: Current implementation complete ✓
2. **Week 2**: Populate arsenal (75k+ payloads)
3. **Week 3**: Add context matcher with ML scoring
4. **Week 4**: Implement mutation engine for WAF bypass
5. **Week 5**: Mobile-specific offensive techniques

See `IMPLEMENTATION_ROADMAP.md` for detailed schedule.
