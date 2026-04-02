import warnings


def test_no_pydantic_v1_validator_deprecation_warning():
    """Importing main.py must not emit PydanticDeprecatedSince20 warnings.

    @validator is deprecated in Pydantic V2 and will error in V3.
    Use @field_validator with @classmethod instead.
    """
    import sys
    import os
    os.environ.setdefault("ONEINFINITY_API_KEY", "")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        # Force reimport to capture import-time warnings
        mods_to_remove = [k for k in sys.modules if "web.backend.main" in k or k == "web.backend.main"]
        for mod in mods_to_remove:
            del sys.modules[mod]

        import web.backend.main  # noqa: F401

    pydantic_warnings = [
        str(w.message) for w in caught
        if "PydanticDeprecated" in str(w.category)
        or "@validator" in str(w.message)
        or "deprecated" in str(w.message).lower()
        and "validator" in str(w.message).lower()
    ]

    assert not pydantic_warnings, (
        f"Pydantic V1 deprecation warnings found:\n"
        + "\n".join(pydantic_warnings)
    )


def test_publish_report_model_instantiates_cleanly():
    """PublishReportRequest must be instantiable without deprecation warnings."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        from web.backend.main import PublishReportRequest
        # Try to instantiate with minimal valid data
        try:
            req = PublishReportRequest(
                scan_id="test-scan",
                sections=["exec", "findings"],
            )
        except Exception:
            pass  # validation errors are fine, deprecation warnings are not

    pydantic_warnings = [
        str(w.message) for w in caught
        if "PydanticDeprecated" in str(w.category) or "@validator" in str(w.message)
    ]
    assert not pydantic_warnings, f"Deprecation warnings: {pydantic_warnings}"
