import os
import shutil
import tempfile
import pytest
from oneinfinity.mobile.sdk_scanner import SDKScanner

def test_sdk_scanner_detects_okhttp():
    temp_dir = tempfile.mkdtemp()
    try:
        # Create a mock directory structure for OkHttp
        okhttp_dir = os.path.join(temp_dir, "smali", "com", "squareup", "okhttp3")
        os.makedirs(okhttp_dir)
        with open(os.path.join(okhttp_dir, "OkHttpClient.smali"), "w") as f:
            f.write(".class public Lcom/squareup/okhttp3/OkHttpClient;")

        scanner = SDKScanner(extracted_dir=temp_dir)
        findings = scanner.scan()

        assert len(findings) > 0
        assert any("OkHttp" in f.vulnerability for f in findings)
    finally:
        shutil.rmtree(temp_dir)
