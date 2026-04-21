# tests/test_silent_failures.py
import ast, pathlib


def test_no_bare_except_pass_in_unified_engine():
    """unified_scan_engine.py must not have bare except:pass blocks.

    Every exception handler must at minimum log the error so failures
    are visible to operators. Swallowing exceptions silently makes
    debugging impossible and lets scans 'succeed' with zero findings
    when every tool is broken.
    """
    PROJECT_ROOT = pathlib.Path(__file__).parent.parent
    src = (
        PROJECT_ROOT / "src/oneinfinity/scan/unified_scan_engine.py"
    ).read_text()
    tree = ast.parse(src)

    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            # Bare except:pass — body is a single Pass statement
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                violations.append(f"  line {node.lineno}: bare except: pass")

    assert not violations, (
        f"Found {len(violations)} silent except:pass blocks in unified_scan_engine.py.\n"
        "Replace each with: except Exception as exc: log.warning('...: %s', exc)\n"
        + "\n".join(violations[:20])
    )
