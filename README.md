# PHP Vulnerability Scanner

A single-file Python tool that checks a PHP codebase two ways:

1. **Version / CVE check** — compares a PHP version against a bundled database of known CVEs, including the **October 2026 unauthenticated remote-code-execution advisories** ([CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)), plus end-of-life branch warnings.
2. **Source code scan (SAST)** — walks `.php` files and flags insecure patterns: SQL injection, command injection, reflected XSS, file inclusion, insecure deserialization, weak crypto, hardcoded secrets, disabled TLS verification and more.

It produces a scored HTML report with code snippets, CWE references and a fix for each finding. Read-only: it reads files and never executes the code it scans.

**[View the sample report →](https://aayyagar.github.io/php-vuln-scanner/sample-report/)**

## The October 2026 PHP advisories

On 21 October 2026 the PHP project disclosed two critical vulnerabilities that can allow **unauthenticated remote code execution** on any installation serving web requests (PHP-FPM, mod_php, php-cgi, FrankenPHP, LiteSpeed), with the highest risk under mod_php. The only complete fix is updating:

| Branch | Patched version |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |

PHP 8.1 and older no longer receive fixes from the project. This scanner flags any version below these as critically vulnerable.

## Quick start

```bash
# See it work on a built-in vulnerable sample
python3 php_vuln_scanner.py --demo --html report.html

# Check a PHP version against the CVE database
python3 php_vuln_scanner.py --version 8.3.20

# Scan a codebase for insecure patterns
python3 php_vuln_scanner.py --path ./my-php-app --html report.html

# Both at once, with a JSON export
python3 php_vuln_scanner.py --path ./app --version 8.3.20 --html report.html --json findings.json
```

No dependencies — standard library only, Python 3.8+.

## What the source scan looks for

| Rule | Severity | Issue | CWE |
|---|---|---|---|
| SQLI-01/02 | Critical | Request data concatenated into SQL | CWE-89 |
| CMDI-01/02 | Critical | OS command injection via `system`/backticks | CWE-78 |
| CODE-01/02 | Critical/High | `eval()`, dynamic code execution | CWE-95 |
| RFI-01 | Critical | File inclusion from user input | CWE-98 |
| XSS-01/02 | High | Unescaped request data echoed to output | CWE-79 |
| LFI-02 | High | File read/write with request-controlled path | CWE-22 |
| DESER-01 | High | `unserialize()` of untrusted input | CWE-502 |
| SSRF-01 | High | Request-controlled outbound URL | CWE-918 |
| CRYPTO-01/02/03 | High/Medium | Weak hash, insecure randomness, weak cipher | CWE-327/338 |
| SECRET-01 | High | Hardcoded credential or API key | CWE-798 |
| SSL-01 | High | TLS certificate verification disabled | CWE-295 |
| XXE-01 | High | XML parsing that may allow external entities | CWE-611 |
| HEADER-01 | Medium | Header/redirect built from request data | CWE-113 |
| UPLOAD-01 | Medium | File upload without apparent validation | CWE-434 |
| CONF-01 | Medium | Errors displayed to users | CWE-209 |

When a sanitizer (`htmlspecialchars`, `escapeshellarg`, a prepared statement, `intval`, …) appears on the same line, the finding is softened one severity band to reduce false positives.

## Use it in CI

The scanner exits non-zero when it finds an issue at or above `--fail-on` (default `Critical`), so it can gate a pipeline:

```bash
python3 php_vuln_scanner.py --path ./src --version "$(php -r 'echo PHP_VERSION;')" --fail-on High
```

## Keeping the CVE data current

Version findings come from [`php_cve_db.json`](php_cve_db.json). Update that file as new advisories land at [php.net](https://www.php.net/). The source-code rules do not depend on it.

## Limitations

This is a fast, pattern-based scanner, not a full dataflow analysis. It is excellent at catching the common, high-impact mistakes and at flagging out-of-date PHP, but it can produce false positives and will not catch vulnerabilities that span multiple files or functions. Review each finding in context, and pair it with a dedicated SAST tool for deep analysis on critical applications.

## Tests

```bash
python3 tests/test_scanner.py
```

## Author

**Akhilesh Ayyagari**, Cloud Infrastructure & Identity Architect · [Portfolio](https://aayyagar.github.io) · [LinkedIn](https://www.linkedin.com/in/akhilesh-ayyagari)

## License

MIT
