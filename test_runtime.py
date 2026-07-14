#!/usr/bin/env python3
"""Runtime error test suite for Subdom.py"""
import sys
import traceback

results = []

def test(name, func):
    try:
        func()
        results.append((name, "PASS", ""))
        print(f"  [PASS] {name}")
    except Exception as e:
        results.append((name, "FAIL", str(e)))
        print(f"  [FAIL] {name}: {e}")
        traceback.print_exc()

print("=" * 60)
print("  SUBDOM RUNTIME ERROR TEST SUITE")
print("=" * 60)

# --- Test 1: Module Import ---
def test_import():
    import Subdom
    assert hasattr(Subdom, 'SCAN_STATE')
    assert hasattr(Subdom, 'RATE_LIMITER')
    assert hasattr(Subdom, 'CIRCUIT_BREAKER')
    assert hasattr(Subdom, 'DEDUP')
    assert hasattr(Subdom, 'PERF')
    assert hasattr(Subdom, 'WAF_PROFILE')
    assert hasattr(Subdom, 'JITTER')
test("Module import + global objects", test_import)

# --- Test 2: Constants ---
def test_constants():
    import Subdom
    assert len(Subdom.USER_AGENTS) > 0
    assert len(Subdom.WAF_BYPASS_HEADERS) > 0
    assert len(Subdom.SUBDOMAIN_WORDS) > 0
    assert len(Subdom.DIR_WORDS) > 0
    assert len(Subdom.API_PATHS) > 0
    assert len(Subdom.INFO_DISCLOSURE_PATHS) > 0
    assert len(Subdom.SCAN_PROFILES) > 0
    assert len(Subdom.TAKEOVER_SIGNATURES) > 0
    assert len(Subdom.WAF_SIGNATURES) > 0
    assert len(Subdom.SECURITY_HEADERS) > 0
test("Constants loaded correctly", test_constants)

# --- Test 3: ANSI Color System ---
def test_colors():
    import Subdom
    assert Subdom.C.RED != ""
    assert Subdom.C.GREEN != ""
    assert Subdom.C.RESET != ""
    assert Subdom.C.BOLD != ""
test("ANSI color system", test_colors)

# --- Test 4: ScanState ---
def test_scan_state():
    import Subdom
    state = Subdom.ScanState()
    assert not state.is_shutdown()
    state.save_partial("test_key", {"data": "test"})
    assert state.get_partial("test_key") == {"data": "test"}
    assert state.get_partial("nonexistent") is None
    state.request_shutdown()
    assert state.is_shutdown()
test("ScanState lifecycle", test_scan_state)

# --- Test 5: DedupEngine ---
def test_dedup():
    import Subdom
    dedup = Subdom.DedupEngine()
    assert not dedup.is_duplicate(200, 1000, "hello world", "/test")
    assert dedup.is_duplicate(200, 1000, "hello world", "/test2")  # Same content
    assert not dedup.is_duplicate(200, 1001, "hello world", "/test3")  # Different size
    assert not dedup.is_path_duplicate("/admin")
    assert dedup.is_path_duplicate("/admin")  # Same path
    stats = dedup.stats()
    assert "unique_content" in stats
    assert "paths_tested" in stats
    assert "suppressed" in stats
test("DedupEngine", test_dedup)

# --- Test 6: False Positive Filter ---
def test_fp_filter():
    import Subdom
    assert Subdom.is_false_positive(200, 10, "", "")  # Too small
    assert Subdom.is_false_positive(200, 500, "Page Not Found - 404", "")  # Body pattern
    assert Subdom.is_false_positive(200, 500, "", "Default Web Site")  # Title pattern
    assert not Subdom.is_false_positive(200, 500, "Welcome to my app", "My App")  # Real page
    assert not Subdom.is_false_positive(404, 0, "", "")  # 404 is not FP (already filtered)
    assert not Subdom.is_false_positive(301, 0, "", "")  # Redirect
test("False positive filter", test_fp_filter)

# --- Test 7: PerfMonitor ---
def test_perf():
    import Subdom
    monitor = Subdom.PerfMonitor()
    for _ in range(100):
        monitor.record_request(success=True)
    monitor.record_request(success=False)
    stats = monitor.get_stats()
    assert stats["requests"] == 101
    assert stats["errors"] == 1
    assert "rps" in stats
    assert "error_rate" in stats
test("PerfMonitor", test_perf)

# --- Test 8: Rate Limiter ---
def test_rate_limiter():
    import Subdom
    limiter = Subdom.RateLimiter()
    limiter.record_success("test")
    limiter.record_failure("test", 429)
    limiter.record_failure("test", 429)
    limiter.record_success("test")
    assert limiter._consecutive_fails.get("test", 0) == 0
test("RateLimiter", test_rate_limiter)

# --- Test 9: Circuit Breaker ---
def test_circuit_breaker():
    import Subdom
    cb = Subdom.CircuitBreaker(threshold=3, cooldown=1)
    assert not cb.is_open("test")
    cb.record_failure("test")
    cb.record_failure("test")
    assert not cb.is_open("test")  # Not yet at threshold
    cb.record_failure("test")
    assert cb.is_open("test")  # Threshold reached
    cb.record_success("test")
    assert not cb.is_open("test")  # Reset
test("CircuitBreaker", test_circuit_breaker)

# --- Test 10: WAF Profile ---
def test_waf_profile():
    import Subdom
    wp = Subdom.WAFProfile()
    assert wp.get_threads(10) == 10
    wp.set_waf("Cloudflare")
    assert wp.get_threads(10) == 3  # 10 * 0.3
    assert wp.get_delay() == 1.5  # 0.5 * 3.0
test("WAFProfile", test_waf_profile)

# --- Test 11: Request Jitter ---
def test_jitter():
    import Subdom
    j = Subdom.RequestJitter(min_ms=10, max_ms=20)
    import time
    start = time.time()
    j.wait()
    elapsed = time.time() - start
    assert 0.005 < elapsed < 0.1  # Should be between 5ms and 100ms
test("RequestJitter", test_jitter)

# --- Test 12: normalize_target ---
def test_normalize():
    import Subdom
    assert Subdom.normalize_target("https://www.example.com") == "example.com"
    assert Subdom.normalize_target("https://api.example.com") == "example.com"
    assert Subdom.normalize_target("https://mail.example.com") == "example.com"
    assert Subdom.normalize_target("example.com") == "example.com"
    assert Subdom.normalize_target("https://sub.example.com/path") == "sub.example.com"
test("normalize_target", test_normalize)

# --- Test 13: validate_domain ---
def test_validate():
    import Subdom
    assert Subdom.validate_domain("example.com")
    assert Subdom.validate_domain("sub.example.com")
    assert Subdom.validate_domain("a.b.c.example.com")
    assert not Subdom.validate_domain("-invalid.com")
    assert not Subdom.validate_domain("invalid-.com")
    assert not Subdom.validate_domain("")
    assert not Subdom.validate_domain("just spaces")
test("validate_domain", test_validate)

# --- Test 14: sanitize_path_component ---
def test_sanitize():
    import Subdom
    assert Subdom.sanitize_path_component("test") == "test"
    assert Subdom.sanitize_path_component("test/path") == "test_path"
    assert Subdom.sanitize_path_component("test<>path") == "test__path"
    assert Subdom.sanitize_path_component("test:file") == "test_file"
test("sanitize_path_component", test_sanitize)

# --- Test 15: load_wordlist ---
def test_wordlist():
    import Subdom
    words = Subdom.load_wordlist("nonexistent.txt", ["default1", "default2"])
    assert words == ["default1", "default2"]
    words = Subdom.load_wordlist("subdomains.txt", ["default"])
    assert len(words) > 0  # File exists
test("load_wordlist", test_wordlist)

# --- Test 16: atomic_write ---
def test_atomic_write():
    import Subdom
    import os
    test_file = "bug_bounty_output/test_atomic.txt"
    Subdom.atomic_write(test_file, "hello world")
    assert os.path.exists(test_file)
    with open(test_file, "r") as f:
        assert f.read() == "hello world"
    # Test overwrite
    Subdom.atomic_write(test_file, "updated content")
    with open(test_file, "r") as f:
        assert f.read() == "updated content"
    os.remove(test_file)
test("atomic_write", test_atomic_write)

# --- Test 17: JSONLWriter ---
def test_jsonl():
    import Subdom
    test_file = "bug_bounty_output/test_jsonl.jsonl"
    writer = Subdom.JSONLWriter(test_file)
    writer.write({"test": "data1"})
    writer.write({"test": "data2"})
    import os
    assert os.path.exists(test_file)
    with open(test_file, "r") as f:
        lines = f.readlines()
    assert len(lines) == 2
    import json
    assert json.loads(lines[0])["test"] == "data1"
    assert json.loads(lines[1])["test"] == "data2"
    os.remove(test_file)
test("JSONLWriter", test_jsonl)

# --- Test 18: load_config ---
def test_config():
    import Subdom
    config = Subdom.load_config("nonexistent.yaml")
    assert config["threads"] == 10
    assert config["timeout"] == 5
    assert "features" in config
test("load_config defaults", test_config)

# --- Test 19: backoff_sleep ---
def test_backoff():
    import Subdom
    import time
    start = time.time()
    Subdom.backoff_sleep(0, base=0.01, cap=0.1)
    elapsed = time.time() - start
    assert elapsed < 0.5  # Should be fast
test("backoff_sleep", test_backoff)

# --- Test 20: get_session ---
def test_session():
    import Subdom
    session = Subdom.get_session()
    assert session is not None
    session2 = Subdom.get_session()
    assert session is session2  # Should reuse
test("get_session pooling", test_session)

# --- Test 21: Scan Profiles ---
def test_profiles():
    import Subdom
    for name, profile in Subdom.SCAN_PROFILES.items():
        assert "description" in profile
        assert "flags" in profile
        assert isinstance(profile["flags"], dict)
test("Scan profiles valid", test_profiles)

# --- Test 22: WAF Signatures ---
def test_waf_sigs():
    import Subdom
    for name, sigs in Subdom.WAF_SIGNATURES.items():
        assert "headers" in sigs or "body" in sigs
        assert isinstance(sigs.get("headers", []), list)
        assert isinstance(sigs.get("body", []), list)
test("WAF signatures valid", test_waf_sigs)

# --- Test 23: Takeover Signatures ---
def test_takeover_sigs():
    import Subdom
    for service, sigs in Subdom.TAKEOVER_SIGNATURES.items():
        assert isinstance(sigs, list)
        assert len(sigs) > 0
        for sig in sigs:
            assert isinstance(sig, str)
test("Takeover signatures valid", test_takeover_sigs)

# --- Test 24: Security Headers ---
def test_sec_headers():
    import Subdom
    for header, info in Subdom.SECURITY_HEADERS.items():
        assert "severity" in info
        assert "desc" in info
        assert info["severity"] in ("HIGH", "MEDIUM", "LOW")
test("Security headers valid", test_sec_headers)

# --- Test 25: Plugin System ---
def test_plugins():
    import Subdom
    plugins = Subdom.load_plugins()
    assert isinstance(plugins, list)  # Empty is fine
test("Plugin system (empty)", test_plugins)

# --- Summary ---
print("\n" + "=" * 60)
passed = sum(1 for _, status, _ in results if status == "PASS")
failed = sum(1 for _, status, _ in results if status == "FAIL")
print(f"  RESULTS: {passed}/{len(results)} passed, {failed} failed")
if failed > 0:
    print("\n  FAILED TESTS:")
    for name, status, error in results:
        if status == "FAIL":
            print(f"    - {name}: {error}")
print("=" * 60)

sys.exit(0 if failed == 0 else 1)
