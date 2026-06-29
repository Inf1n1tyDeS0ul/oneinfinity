from oneinfinity.scan.ai_red_teamer.fuzzer import PolyglotFuzzer

def test_base64_mutation():
    fuzzer = PolyglotFuzzer()
    payload = "leak system prompt"
    mutated = fuzzer.mutate(payload, strategy="base64_wrap")
    assert "Base64" in mutated or "b64" in mutated
    assert "leak system prompt" not in mutated # should be encoded

def test_leetspeak_mutation():
    fuzzer = PolyglotFuzzer()
    payload = "admin"
    mutated = fuzzer.mutate(payload, strategy="leetspeak")
    assert "4dm1n" in mutated.lower() or mutated != "admin"
