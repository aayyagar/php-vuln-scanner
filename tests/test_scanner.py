"""Minimal self-tests for php_vuln_scanner (run: python3 -m pytest tests/ or python3 tests/test_scanner.py)."""
import os, sys, tempfile, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import php_vuln_scanner as s

DB = json.load(open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "php_cve_db.json")))

def test_vulnerable_version_flags_cves():
    f = s.version_check("8.3.20", DB)
    ids = [x.rule for x in f]
    assert "CVE-2026-109618" in ids and "CVE-2026-109619" in ids

def test_patched_version_clean():
    f = s.version_check("8.4.27", DB)
    assert all(x.severity == "Info" for x in f)

def test_eol_branch_flagged():
    f = s.version_check("8.1.9", DB)
    assert any(x.rule == "VER-EOL" for x in f)

def test_code_scan_detects_sqli_and_cmdi():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "a.php"), "w").write(
            '<?php $x = mysqli_query($c, "SELECT * FROM t WHERE id=".$_GET["id"]); system($_POST["h"]);')
        findings, n = s.scan_path(d)
        rules = {x.rule for x in findings}
        assert n == 1
        assert "SQLI-02" in rules and "CMDI-01" in rules

def test_sanitized_echo_softened():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "b.php"), "w").write('<?php echo htmlspecialchars($_GET["q"]);')
        findings, _ = s.scan_path(d)
        xss = [x for x in findings if x.rule == "XSS-01"]
        assert xss and xss[0].severity == "Medium"  # softened from High by sanitizer hint

def test_score_bounds():
    assert s.score([]) == 100
    assert 0 <= s.score(s.version_check("8.3.20", DB)) <= 100

if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn(); passed += 1; print(f"  PASS {fn.__name__}")
    print(f"\n  {passed}/{len(fns)} tests passed")
