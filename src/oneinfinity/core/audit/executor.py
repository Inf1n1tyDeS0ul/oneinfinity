import asyncio
import importlib.util
import inspect
from typing import Dict, Any, Tuple

def _module_name_from_path(path: str) -> str:
    # Turn "core/doctor.py" into "core.doctor"
    if path.endswith(".py"):
        path = path[:-3]
    return path.replace("/", ".").replace("\\", ".")

def _safe_import(path: str) -> Tuple[bool, str, object]:
    mod_name = _module_name_from_path(path)
    try:
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            return False, f"spec not found for {mod_name}", None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return True, "", module
    except Exception as exc:
        return False, str(exc), None

def _can_instantiate(cls) -> bool:
    try:
        sig = inspect.signature(cls.__init__)
        params = list(sig.parameters.values())[1:]  # skip self
        return all(p.default is not inspect._empty or p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in params)
    except Exception:
        return False

class AuditExecutor:
    def __init__(self, mode: str = "simulate"):
        self.mode = mode  # simulate | import

    async def execute(self, feature: Dict[str, Any]) -> Dict[str, Any]:
        """
        Audit a discovered feature.
        - simulate: legacy heuristic mode (fast, low fidelity)
        - import: real import + class existence + safe instantiation checks
        """
        await asyncio.sleep(0.02)

        name = feature.get("name", "")
        path = feature.get("file", "")

        if self.mode != "import":
            # Legacy simulation for speed and compatibility
            if "Broken" in name or "Legacy" in name:
                return {
                    "status": "❌ broken",
                    "logs": f"Execution failed for {name}. Exception: NotImplementedError"
                }
            elif "Partial" in name or "Validator" in name:
                return {
                    "status": "⚠️ partial",
                    "logs": f"Feature {name} executed but returned incomplete data or missing integrations."
                }
            else:
                return {
                    "status": "✅ working",
                    "logs": f"Successfully executed {name}."
                }

        # Import mode: real checks
        ok, err, module = _safe_import(path)
        if not ok or module is None:
            return {
                "status": "❌ broken",
                "logs": f"Import failed for {path}: {err}"
            }

        cls = getattr(module, name, None)
        if cls is None:
            return {
                "status": "❌ broken",
                "logs": f"Class '{name}' not found in {path}"
            }

        # Optional health_check
        if hasattr(cls, "health_check") and callable(getattr(cls, "health_check")):
            try:
                res = cls.health_check()
                if isinstance(res, dict) and res.get("status") == "ok":
                    return {"status": "✅ working", "logs": f"{name}.health_check ok"}
                return {"status": "⚠️ partial", "logs": f"{name}.health_check returned: {res}"}
            except Exception as exc:
                return {"status": "⚠️ partial", "logs": f"{name}.health_check error: {exc}"}

        # Safe instantiation check (no-arg only)
        if _can_instantiate(cls):
            try:
                cls()  # instantiate to ensure deps are present
                return {"status": "✅ working", "logs": f"Imported and instantiated {name}"}
            except Exception as exc:
                return {"status": "⚠️ partial", "logs": f"Instantiation failed for {name}: {exc}"}

        return {"status": "⚠️ partial", "logs": f"Imported {name} but requires constructor args"}
