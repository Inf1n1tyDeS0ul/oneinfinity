# tests/test_pipeline_parity.py
import inspect
import sys


def test_unified_engine_has_business_logic_phase():
    """unified_scan_engine must include a business_logic phase.

    The canonical pipeline has business_logic as phase 6.
    Users scanning via the API (which uses unified_scan_engine) must
    get the same coverage as users running full-scan CLI.
    """
    import oneinfinity.unified_scan_engine as unified_scan_engine
    src = inspect.getsource(unified_scan_engine)
    assert "business_logic" in src, (
        "unified_scan_engine.py is missing the business_logic phase. "
        "The canonical pipeline (pipeline/canonical.py) includes it as phase 6. "
        "Add a _phase_business_logic() method and include it in the phase list."
    )


def test_unified_engine_has_oob_check_phase():
    """unified_scan_engine must include an OOB check phase."""
    import oneinfinity.unified_scan_engine as unified_scan_engine
    src = inspect.getsource(unified_scan_engine)
    assert "oob_check" in src or "oob" in src.lower(), (
        "unified_scan_engine.py appears to be missing OOB check functionality."
    )


def test_business_logic_phase_method_exists():
    """The _phase_business_logic method must be callable."""
    from oneinfinity.unified_scan_engine import UnifiedScanEngine
    engine = UnifiedScanEngine.__new__(UnifiedScanEngine)
    assert hasattr(engine, '_phase_business_logic'), (
        "UnifiedScanEngine must have a _phase_business_logic method"
    )
    assert callable(getattr(engine, '_phase_business_logic')), (
        "_phase_business_logic must be callable"
    )
