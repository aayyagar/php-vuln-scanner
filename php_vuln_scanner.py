#!/usr/bin/env python3
"""
PHP Vulnerability Scanner
=========================

Two scans in one tool:

1. Version / CVE check  - compares a PHP version against a bundled database of known CVEs
   (including the October 2026 unauthenticated-RCE advisories) and end-of-life branches.

2. Source code scan (SAST) - walks a directory of .php files and flags insecure patterns:
   SQL injection, command injection, reflected XSS, LFI/RFI, insecure deserialization,
   weak crypto, hardcoded secrets, dangerous functions and more.

Read-only. It reads files and prints findings; it never executes the code it scans.

Usage:
    python3 php_vuln_scanner.py --version 8.3.20
    python3 php_vuln_scanner.py --path ./my-php-app
    python3 php_vuln_scanner.py --path ./app --version 8.3.20 --html report.html
    python3 php_vuln_scanner.py --demo --html report.html

Author:  Akhilesh Ayyagari (github.com/aayyagar)
License: MIT
"""
from __future__ import annotations
import argparse
import html
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

VERSION = "1.0.0"
HERE = os.path.dirname(os.path.abspath(__file__))

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_WEIGHT = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2, "Info": 0}


# --------------------------------------------------------------------------------------
#  Finding model
# --------------------------------------------------------------------------------------
@dataclass
class Finding:
    kind: str            # "version" or "code"
    rule: str
    severity: str
    title: str
    detail: str
    location: str = ""
    line: int = 0
    snippet: str = ""
    recommendation: str = ""
    cwe: str = ""


# --------------------------------------------------------------------------------------
#  Version / CVE check
# --------------------------------------------------------------------------------------
def parse_version(v: str):
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", v.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def branch_of(v: str) -> str:
    p = parse_version(v)
    return f"{p[0]}.{p[1]}" if p else ""


def version_check(version: str, db: dict) -> list[Finding]:
    out: list[Finding] = []
    pv = parse_version(version)
    if not pv:
        out.append(Finding("version", "VER-PARSE", "Info", "Could not parse PHP version",
                            f"'{version}' is not a recognizable PHP version string.", recommendation="Pass a version like 8.3.20."))
        return out
    branch = branch_of(version)

    # End-of-life branch?
    eol = db.get("eol_branches", {})
    if branch in eol:
        out.append(Finding("version", "VER-EOL", "High", f"PHP {branch} is end-of-life",
                            f"PHP {branch} stopped receiving security fixes on {eol[branch]}. Running it means no patches for new vulnerabilities.",
                            recommendation="Upgrade to a supported branch (8.4 or 8.5) and keep it patched."))

    # Known CVEs affecting this version
    for cve in db.get("cves", []):
        fixed = cve.get("fixed", {}).get(branch)
        affected = False
        if fixed:
            fv = parse_version(fixed)
            if fv and pv < fv:
                affected = True
        elif branch in eol:
            # EOL branch below all fixed branches - treat as affected by RCE-class CVEs
            affected = True
        if affected:
            fix_txt = f"Update to PHP {fixed} or later." if fixed else "This branch is end-of-life; upgrade to a supported, patched branch."
            out.append(Finding("version", cve["id"], cve["severity"], cve["title"],
                               cve["description"], location=f"PHP {version}",
                               recommendation=fix_txt + f'  Reference: {cve.get("ref","")}'))

    # Below the minimum safe patch of its own branch?
    msp = db.get("min_safe_patch", {}).get(branch)
    if msp and not any(f.kind == "version" and f.rule.startswith("CVE") for f in out):
        mv = parse_version(msp)
        if mv and pv < mv:
            out.append(Finding("version", "VER-PATCH", "Medium", f"PHP {version} is behind the latest patch",
                               f"The latest secure patch for the {branch} branch is {msp}.",
                               recommendation=f"Update to PHP {msp} or later."))

    if not out:
        out.append(Finding("version", "VER-OK", "Info", f"PHP {version} has no known issues in this database",
                           f"PHP {version} is at or above the latest patch in the bundled database (updated {db.get('updated','')}).",
                           recommendation="Keep PHP patched and re-check against the live advisories at php.net."))
    return out


# --------------------------------------------------------------------------------------
#  Source code scan (regex-based SAST)
# --------------------------------------------------------------------------------------
# Each rule: (id, severity, title, compiled regex, recommendation, cwe)
# Patterns look for tainted input flowing into dangerous sinks, and insecure APIs.
SUPERGLOBAL = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"

CODE_RULES = [
    ("SQLI-01", "Critical", "Possible SQL injection",
     re.compile(r"(?:query|exec|prepare)\s*\(\s*[\"'][^\"']*\.\s*" + SUPERGLOBAL, re.I),
     "Use prepared statements with bound parameters (PDO or mysqli), never string concatenation with request data.", "CWE-89"),
    ("SQLI-02", "Critical", "Request data concatenated into SQL string",
     re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^;]*?\.\s*" + SUPERGLOBAL, re.I),
     "Parameterize the query. Do not build SQL by concatenating superglobals.", "CWE-89"),
    ("CMDI-01", "Critical", "Possible OS command injection",
     re.compile(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^)]*" + SUPERGLOBAL, re.I),
     "Avoid passing user input to shell functions. If unavoidable, use escapeshellarg()/escapeshellcmd() and an allowlist.", "CWE-78"),
    ("CMDI-02", "Critical", "Backtick shell execution with request data",
     re.compile(r"`[^`]*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
     "Remove backtick execution of user input; use an allowlisted command with escaped arguments.", "CWE-78"),
    ("CODE-01", "Critical", "Dynamic code execution (eval) with request data",
     re.compile(r"\beval\s*\([^)]*" + SUPERGLOBAL, re.I),
     "Never eval() user input. Redesign to avoid dynamic code execution.", "CWE-95"),
    ("CODE-02", "High", "Use of eval()",
     re.compile(r"\beval\s*\("),
     "Avoid eval() entirely; it is almost always replaceable with safer constructs.", "CWE-95"),
    ("RFI-01", "Critical", "Possible remote/local file inclusion",
     re.compile(r"\b(?:include|include_once|require|require_once)\s*\(?\s*[^;]*" + SUPERGLOBAL, re.I),
     "Never include a path built from user input. Use a fixed allowlist of includable files.", "CWE-98"),
    ("XSS-01", "High", "Possible reflected XSS (echo of request data)",
     re.compile(r"\b(?:echo|print)\b[^;]*" + SUPERGLOBAL, re.I),
     "Encode output with htmlspecialchars(..., ENT_QUOTES) or a templating engine with auto-escaping.", "CWE-79"),
    ("XSS-02", "High", "Request data written to output buffer",
     re.compile(r"(?:printf|fwrite|print_r)\s*\([^)]*" + SUPERGLOBAL, re.I),
     "Encode user input before writing it to a response.", "CWE-79"),
    ("LFI-02", "High", "File read/write with request-controlled path",
     re.compile(r"\b(?:file_get_contents|file_put_contents|fopen|readfile|unlink|fwrite)\s*\([^)]*" + SUPERGLOBAL, re.I),
     "Validate and canonicalize paths; use an allowlist and basename(); never trust request paths.", "CWE-22"),
    ("DESER-01", "High", "Insecure deserialization of request data",
     re.compile(r"\bunserialize\s*\([^)]*" + SUPERGLOBAL, re.I),
     "Do not unserialize() untrusted input. Use json_decode() for data interchange.", "CWE-502"),
    ("SSRF-01", "High", "Possible SSRF (request-controlled URL fetch)",
     re.compile(r"\b(?:curl_setopt|file_get_contents|fsockopen)\s*\([^)]*CURLOPT_URL[^)]*" + SUPERGLOBAL, re.I),
     "Validate outbound URLs against an allowlist of hosts; block internal addresses.", "CWE-918"),
    ("CRYPTO-01", "High", "Weak hashing algorithm",
     re.compile(r"\b(?:md5|sha1)\s*\(", re.I),
     "Use password_hash()/password_verify() for passwords, and SHA-256+ for integrity.", "CWE-327"),
    ("CRYPTO-02", "Medium", "Insecure randomness for security use",
     re.compile(r"\b(?:mt_rand|rand|uniqid)\s*\("),
     "Use random_bytes() or random_int() for tokens, IDs and secrets.", "CWE-338"),
    ("CRYPTO-03", "High", "Weak cipher (DES/ECB/RC4)",
     re.compile(r"(?:MCRYPT_DES|['\"]des-ecb['\"]|['\"]rc4['\"]|ECB)", re.I),
     "Use AES-256-GCM via OpenSSL/Sodium with a random IV; never ECB.", "CWE-327"),
    ("SECRET-01", "High", "Hardcoded credential or secret",
     re.compile(r"(?:password|passwd|pwd|secret|api[_-]?key|token|aws_secret)\s*=\s*[\"'][^\"']{6,}[\"']", re.I),
     "Move secrets to environment variables or a secrets manager; never commit them.", "CWE-798"),
    ("SSL-01", "High", "TLS certificate verification disabled",
     re.compile(r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:0|false)", re.I),
     "Leave CURLOPT_SSL_VERIFYPEER/HOST enabled; fix the trust store instead of disabling verification.", "CWE-295"),
    ("CONF-01", "Medium", "Errors displayed to users",
     re.compile(r"display_errors\s*,\s*(?:1|['\"]on['\"])|error_reporting\s*\(\s*E_ALL\s*\)", re.I),
     "Disable display_errors in production; log errors instead.", "CWE-209"),
    ("UPLOAD-01", "Medium", "File upload without apparent type/extension check",
     re.compile(r"move_uploaded_file\s*\(", re.I),
     "Validate the MIME type and extension against an allowlist, store outside the web root, and randomize the name.", "CWE-434"),
    ("XXE-01", "High", "XML parsing that may allow external entities",
     re.compile(r"\b(?:simplexml_load_string|simplexml_load_file|DOMDocument)\b", re.I),
     "Disable external entity loading (libxml_disable_entity_loader or LIBXML_NONET) when parsing untrusted XML.", "CWE-611"),
    ("HEADER-01", "Medium", "HTTP header built from request data (header injection / open redirect)",
     re.compile(r"\bheader\s*\(\s*[^)]*" + SUPERGLOBAL, re.I),
     "Validate against an allowlist before using request data in a header, especially Location redirects.", "CWE-113"),
]

# Patterns that usually mean the line is safe - reduce obvious false positives.
SAFE_HINTS = re.compile(r"htmlspecialchars|htmlentities|escapeshellarg|escapeshellcmd|->prepare\(|filter_input|preg_match|intval|\(int\)", re.I)


def scan_file(path: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as e:
        return [Finding("code", "FILE-ERR", "Info", "Could not read file", str(e), location=rel)]

    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if stripped.startswith(("//", "#", "*")):
            continue
        for rid, sev, title, rx, rec, cwe in CODE_RULES:
            if rx.search(line):
                # Soften severity by one band if a sanitizer appears on the same line.
                eff = sev
                if SAFE_HINTS.search(line) and sev in ("Critical", "High"):
                    eff = "Medium"
                findings.append(Finding("code", rid, eff, title,
                                        f"Matched rule {rid} ({cwe}).",
                                        location=rel, line=i, snippet=stripped[:200],
                                        recommendation=rec, cwe=cwe))
    return findings


def scan_path(root: str, max_bytes: int = 2_000_000) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    nfiles = 0
    exts = (".php", ".php3", ".php4", ".php5", ".phtml", ".inc")
    skip_dirs = {"vendor", "node_modules", ".git", "tests", "test"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            if not fn.lower().endswith(exts):
                continue
            full = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(full) > max_bytes:
                    continue
            except OSError:
                continue
            rel = os.path.relpath(full, root)
            findings.extend(scan_file(full, rel))
            nfiles += 1
    return findings, nfiles


# --------------------------------------------------------------------------------------
#  Scoring
# --------------------------------------------------------------------------------------
def score(findings: list[Finding]) -> int:
    scored = [f for f in findings if f.severity in SEV_WEIGHT and f.severity != "Info"]
    if not scored:
        return 100
    penalty = sum(SEV_WEIGHT[f.severity] for f in scored)
    return max(0, 100 - min(100, penalty))


# --------------------------------------------------------------------------------------
#  Reporting
# --------------------------------------------------------------------------------------
def esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def render_html(findings: list[Finding], php_version: str, scanned_files: int, out: str):
    findings = sorted(findings, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.kind, f.location, f.line))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
    sc = score(findings)
    ring = "var(--ok)" if sc >= 80 else ("var(--warn)" if sc >= 50 else "var(--crit)")
    dash = round(2 * 3.14159 * 52 * sc / 100, 1)

    def row(f: Finding) -> str:
        loc = esc(f.location) + (f":{f.line}" if f.line else "")
        snip = f'<pre class="snip">{esc(f.snippet)}</pre>' if f.snippet else ""
        rec = f'<div class="rec"><span class="lbl">Fix</span>{esc(f.recommendation)}</div>' if f.recommendation else ""
        cwe = f'<span class="cwe">{esc(f.cwe)}</span>' if f.cwe else ""
        return f"""<details class="f {f.severity.lower()}"{' open' if f.severity=='Critical' else ''}>
<summary><span class="pill {f.severity.lower()}">{f.severity}</span><span class="rule">{esc(f.rule)}</span><span class="ttl">{esc(f.title)}</span>{cwe}</summary>
<div class="body"><div class="loc">{loc or esc(f.detail)}</div>{snip}{rec}</div></details>"""

    rows = "\n".join(row(f) for f in findings)
    vline = f"PHP {esc(php_version)}" if php_version else "version check skipped"
    cline = f"{scanned_files} file(s) scanned" if scanned_files else "no source scan"

    css = """
:root{--bg:#f3f4f7;--card:#fff;--ink:#151a2c;--mut:#5b6278;--line:#dcdfe7;--soft:#eef0f4;--crit:#c8432b;--high:#c2691b;--med:#b07a00;--low:#5b6278;--ok:#17865f;--acc:#6b46c1}
@media (prefers-color-scheme:dark){:root{--bg:#0f1220;--card:#181c2e;--ink:#e9ecf4;--mut:#9ca3ba;--line:#2a3048;--soft:#1f2438;--crit:#f07a62;--high:#f0a05f;--med:#e7b43b;--low:#9ca3ba;--ok:#3fc48d;--acc:#a78bfa;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,sans-serif}
.w{max-width:1040px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:flex-end;margin-bottom:18px}
h1{margin:0;font-size:1.7rem;letter-spacing:-.02em}.sub{color:var(--mut);font-size:.82rem}.mono{font-family:Consolas,ui-monospace,monospace;font-size:.8rem;color:var(--mut)}
.top{display:grid;grid-template-columns:220px 1fr;gap:16px;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px}
.score{display:flex;flex-direction:column;align-items:center;gap:4px;text-align:center}.score svg{width:140px;height:140px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.kpi{background:var(--soft);border-radius:10px;padding:12px}.kpi b{display:block;font-size:1.6rem;font-variant-numeric:tabular-nums}.kpi span{font-size:.74rem;color:var(--mut)}
.kpi.crit b{color:var(--crit)}.kpi.high b{color:var(--high)}.kpi.med b{color:var(--med)}.kpi.low b{color:var(--low)}.kpi.info b{color:var(--mut)}
h2{font-size:1.2rem;margin:22px 0 10px}
details.f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--low);border-radius:10px;margin-bottom:8px}
details.f.critical{border-left-color:var(--crit)}details.f.high{border-left-color:var(--high)}details.f.medium{border-left-color:var(--med)}details.f.info{border-left-color:var(--mut)}
summary{display:grid;grid-template-columns:74px 90px 1fr auto;gap:12px;align-items:center;padding:12px 16px;cursor:pointer;list-style:none}summary::-webkit-details-marker{display:none}
.pill{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:3px 9px;border-radius:999px;color:#fff;text-align:center}
.pill.critical{background:var(--crit)}.pill.high{background:var(--high)}.pill.medium{background:var(--med)}.pill.low{background:var(--low)}.pill.info{background:var(--soft);color:var(--mut)}
.rule{font-family:Consolas,ui-monospace,monospace;font-size:.78rem;color:var(--mut)}.ttl{font-weight:600}.cwe{font-size:.7rem;color:var(--mut);border:1px solid var(--line);border-radius:6px;padding:2px 7px}
.body{padding:0 16px 16px 180px}.loc{font-family:Consolas,ui-monospace,monospace;font-size:.82rem;color:var(--mut);margin-bottom:6px}
.snip{background:var(--soft);border-radius:8px;padding:10px 12px;overflow-x:auto;font-size:.8rem;margin:0 0 8px}
.rec{font-size:.88rem}.lbl{display:inline-block;font-size:.68rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);margin-right:6px}
footer{margin-top:24px;font-size:.8rem;color:var(--mut)}
@media (max-width:720px){.top{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(3,1fr)}summary{grid-template-columns:64px 1fr}.rule,.cwe{display:none}.body{padding:0 16px 16px}}
"""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHP Vulnerability Report</title><style>{css}</style></head><body><div class="w">
<header><div><div class="mono">PHP VULNERABILITY SCAN</div><h1>Scan Report</h1><div class="sub">{stamp} &middot; {vline} &middot; {cline}</div></div><div class="mono">php-vuln-scanner v{VERSION}</div></header>
<div class="top">
<div class="card score"><svg viewBox="0 0 120 120" role="img" aria-label="Score {sc}"><circle cx="60" cy="60" r="52" fill="none" stroke="var(--soft)" stroke-width="10"/><circle cx="60" cy="60" r="52" fill="none" stroke="{ring}" stroke-width="10" stroke-linecap="round" stroke-dasharray="{dash} 400" transform="rotate(-90 60 60)"/><text x="60" y="58" text-anchor="middle" font-size="30" font-weight="700" fill="var(--ink)">{sc}</text><text x="60" y="78" text-anchor="middle" font-size="11" fill="var(--mut)">/ 100</text></svg><span class="mono">security score</span></div>
<div class="card"><div class="kpis">
<div class="kpi crit"><b>{counts['Critical']}</b><span>Critical</span></div>
<div class="kpi high"><b>{counts['High']}</b><span>High</span></div>
<div class="kpi med"><b>{counts['Medium']}</b><span>Medium</span></div>
<div class="kpi low"><b>{counts['Low']}</b><span>Low</span></div>
<div class="kpi info"><b>{counts['Info']}</b><span>Info</span></div>
</div></div></div>
<h2>Findings</h2>
{rows if rows else '<div class="card">No findings.</div>'}
<footer>Pattern-based scan: review each finding in context, as automated rules can flag safe code. Version data from the bundled CVE database; re-check against php.net for the latest advisories. Generated by php-vuln-scanner &middot; github.com/aayyagar/php-vuln-scanner</footer>
</div></body></html>"""
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(doc)


# --------------------------------------------------------------------------------------
#  Demo
# --------------------------------------------------------------------------------------
DEMO_PHP = r"""<?php
// Demo file with intentional issues for the scanner
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
echo "Welcome " . $_GET['name'];
system("ping " . $_POST['host']);
include($_GET['page'] . ".php");
$data = unserialize($_COOKIE['prefs']);
$hash = md5($password);
$token = mt_rand();
$apikey = "sk_live_1234567890abcdef";
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
eval($_REQUEST['cmd']);
$safe = htmlspecialchars($_GET['q']); echo $safe;
"""


def run_demo(tmpdir: str):
    os.makedirs(tmpdir, exist_ok=True)
    with open(os.path.join(tmpdir, "index.php"), "w") as fh:
        fh.write(DEMO_PHP)


# --------------------------------------------------------------------------------------
#  Main
# --------------------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="PHP vulnerability scanner: version/CVE check + source SAST.")
    ap.add_argument("--path", help="Directory of PHP source to scan")
    ap.add_argument("--version", help="PHP version to check against the CVE database, e.g. 8.3.20")
    ap.add_argument("--db", default=os.path.join(HERE, "php_cve_db.json"), help="Path to the CVE database JSON")
    ap.add_argument("--html", help="Write an HTML report to this path")
    ap.add_argument("--json", dest="json_out", help="Write findings as JSON to this path")
    ap.add_argument("--demo", action="store_true", help="Scan a built-in vulnerable sample and check PHP 8.3.20")
    ap.add_argument("--fail-on", default="Critical", choices=["Critical", "High", "Medium", "none"],
                    help="Exit non-zero if a finding at this severity or above exists (default Critical)")
    args = ap.parse_args(argv)

    findings: list[Finding] = []
    php_version = args.version or ""
    scanned = 0

    try:
        with open(args.db, "r", encoding="utf-8") as fh:
            db = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: could not load CVE database: {e}", file=sys.stderr)
        return 2

    if args.demo:
        php_version = "8.3.20"
        demo_dir = os.path.join(HERE, "_demo_src")
        run_demo(demo_dir)
        args.path = demo_dir

    if php_version:
        findings += version_check(php_version, db)
    if args.path:
        if not os.path.isdir(args.path):
            print(f"error: --path '{args.path}' is not a directory", file=sys.stderr)
            return 2
        code_findings, scanned = scan_path(args.path)
        findings += code_findings

    if not php_version and not args.path:
        ap.print_help()
        return 2

    # Console summary
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
    sc = score(findings)
    print()
    print(f"  PHP Vulnerability Scanner v{VERSION}")
    if php_version:
        print(f"  PHP version : {php_version}")
    if args.path:
        print(f"  Source scan : {scanned} file(s) in {args.path}")
    print(f"  Score       : {sc}/100")
    print(f"  Findings    : {counts['Critical']} critical, {counts['High']} high, {counts['Medium']} medium, {counts['Low']} low")
    print()
    for f in sorted(findings, key=lambda x: (SEV_ORDER.get(x.severity, 9), x.location, x.line)):
        if f.severity == "Info":
            continue
        loc = f" {f.location}:{f.line}" if f.location else ""
        print(f"  [{f.severity:8}] {f.rule:16} {f.title}{loc}")
    print()

    if args.html:
        render_html(findings, php_version, scanned, args.html)
        print(f"  HTML report : {args.html}")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in findings], fh, indent=2)
        print(f"  JSON        : {args.json_out}")
    print()

    if args.fail_on != "none":
        threshold = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER.get(f.severity, 9) <= threshold for f in findings if f.severity != "Info"):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
