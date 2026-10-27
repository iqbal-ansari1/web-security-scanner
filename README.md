# 🔍 Automated Web Scanner

A lightweight Python command-line tool that audits websites for **missing or weak HTTP security headers**, **insecure cookie flags**, and **CORS misconfigurations**, then produces a scored report with a recommended fix for every issue.

Built as a project for the **IBM Cybersecurity Bootcamp**.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Category](https://img.shields.io/badge/OWASP-A05%20Security%20Misconfiguration-orange)

> ⚠️ **Legal & ethical use only.** Scan only systems you own or have explicit written permission to test. See [Responsible use](#-responsible-use).

---

## 📖 Table of contents

- [Why this project](#-why-this-project)
- [Features](#-features)
- [What it checks](#-what-it-checks)
- [Installation](#-installation)
- [Usage](#-usage)
- [Try it safely with the demo server](#-try-it-safely-with-the-demo-server)
- [Sample output](#-sample-output)
- [Scoring and exit codes](#-scoring-and-exit-codes)
- [Using it in CI/CD](#-using-it-in-cicd)
- [Project structure](#-project-structure)
- [Limitations](#-limitations)
- [Roadmap](#-roadmap)
- [Responsible use](#-responsible-use)
- [References](#-references)
- [License](#-license)

---

## 🎯 Why this project

Security misconfiguration is one of the most common web vulnerabilities (**OWASP Top 10, A05:2021**). Missing headers and overly permissive CORS rules rarely break a site, so they go unnoticed, yet they enable clickjacking, XSS escalation, MIME-sniffing attacks and cross-origin data theft.

This tool automates the manual checks a security analyst would otherwise do with browser dev tools or `curl`.

## ✨ Features

- ✅ Audits **10 security-related headers** with value validation, not just presence
- ✅ Tests **CORS** with crafted `Origin` headers, including bypass techniques
- ✅ Checks `Set-Cookie` flags (`Secure`, `HttpOnly`, `SameSite`)
- ✅ Assigns **severity levels** and a **0–100 score / A–F grade**
- ✅ Gives a **recommended fix** for every finding
- ✅ Scans **multiple targets** from a file
- ✅ Exports **JSON** and **Markdown** reports
- ✅ **CI-friendly** exit codes (`--fail-on`)
- ✅ Includes a **local demo server**, so you can test without touching anyone else's site

## 🧪 What it checks

### Security headers

| Check | Flags when | Severity |
|---|---|---|
| HTTPS | Final URL is plain HTTP | HIGH |
| `Strict-Transport-Security` | Missing on HTTPS, or `max-age` < 180 days | MEDIUM / LOW |
| `Content-Security-Policy` | Missing, or `unsafe-inline` / `unsafe-eval` / `*` in script policy | MEDIUM |
| Clickjacking | No `X-Frame-Options` and no CSP `frame-ancestors` | MEDIUM |
| `X-Content-Type-Options` | Not `nosniff` | LOW |
| `Referrer-Policy` | Missing, or `unsafe-url` / `no-referrer-when-downgrade` | LOW |
| `Permissions-Policy` | Missing | LOW |
| Information disclosure | `Server` with a version number, `X-Powered-By`, `X-AspNet-Version` | LOW |

### Cookies

| Check | Flags when | Severity |
|---|---|---|
| `Secure` | Missing on an HTTPS site | MEDIUM |
| `HttpOnly` / `SameSite` | Missing | LOW |

### CORS

The scanner sends requests with these `Origin` values and inspects `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC):

| Probe | Vulnerability it detects | Severity (with credentials / without) |
|---|---|---|
| `https://evil-attacker.example` | Blindly **reflected origin** | CRITICAL / MEDIUM |
| `null` | `null` origin trusted (sandboxed iframes, `file://`) | HIGH / LOW |
| `https://<target>.evil-attacker.example` | **Suffix-match** validation bug | HIGH / LOW |
| `https://not<target>` | **Prefix/substring** validation bug | HIGH / LOW |
| `http://<target>` | HTTPS site trusts an insecure origin | MEDIUM / LOW |
| `Access-Control-Allow-Origin: *` | Wildcard policy (and the invalid `*` + credentials combo) | LOW / MEDIUM |
| Missing `Vary: Origin` | Cache poisoning of CORS headers | LOW |
| `OPTIONS` preflight | `PUT` / `PATCH` / `DELETE` allowed from an untrusted origin | MEDIUM |

## 🛠 Installation

**Requirements:** Python 3.9+ and `pip`.

```bash
git clone https://github.com/vaibhav-s-gh/web-security-scanner.git
cd web-security-scanner

# (recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

## 🚀 Usage

```bash
# Scan one site
python scanner.py https://example.com

# Scan several sites
python scanner.py https://site-one.com https://site-two.com

# Scan targets listed in a file (one per line, # for comments)
python scanner.py -f targets.txt

# Save reports
python scanner.py https://example.com --json results.json --markdown report.md

# Fail (exit code 1) only on CRITICAL findings
python scanner.py https://example.com --fail-on CRITICAL
```

### Options

| Option | Description |
|---|---|
| `urls` | One or more target URLs (`https://` is assumed if omitted) |
| `-f`, `--file` | File with one target per line |
| `-t`, `--timeout` | Request timeout in seconds (default `10`) |
| `--insecure` | Skip TLS certificate verification (for self-signed lab servers) |
| `--json PATH` | Write results as JSON |
| `--markdown PATH` | Write a Markdown report |
| `--fail-on LEVEL` | Exit `1` if any finding is at or above `INFO/LOW/MEDIUM/HIGH/CRITICAL` (default `HIGH`; `NONE` to disable) |
| `--no-color` | Disable coloured output |

## 🧫 Try it safely with the demo server

The repo ships with `demo_server.py`, a local server that binds to `127.0.0.1` only.

```bash
# Terminal 1: deliberately insecure server (reflects any Origin, no security headers)
python demo_server.py --port 8000

# Terminal 2: scan it
python scanner.py http://127.0.0.1:8000

# Compare with the hardened version
python demo_server.py --secure --port 8001      # Terminal 1
python scanner.py http://127.0.0.1:8001         # Terminal 2
```

Expected results: the insecure server scores **0/100 (F)** with a CRITICAL CORS finding; the hardened server scores **85/100 (B)**. The one remaining finding is "plain HTTP", which is expected because the demo runs on `localhost` without TLS.

Other legal practice targets: your own projects, [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) or [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) running locally, or `http://testphp.vulnweb.com` (intentionally vulnerable, published by Acunetix for testing).

## 📟 Sample output

Scanning the insecure demo server (shortened):

```text
======================================================================
Target : http://127.0.0.1:8000
Status : HTTP 200
Score  : 0/100   Grade: F
======================================================================
[CRITICAL] [cors] Arbitrary origin reflected (with credentials)
    Why : Origin 'https://evil-attacker.example' was echoed in Access-Control-Allow-Origin
          and Access-Control-Allow-Credentials is true. A malicious site could read
          authenticated responses.
    Fix : Validate Origin against an exact allow-list; never reflect it blindly.
[HIGH]     [cors] 'null' origin trusted (with credentials)
[HIGH]     [cors] Origin suffix-match bypass (with credentials)
[MEDIUM]   [header] Missing Content-Security-Policy
    Fix : Start with: Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
[MEDIUM]   [cors] Preflight allows state-changing methods from untrusted origin
[LOW]      [header] Missing X-Content-Type-Options
[LOW]      [cookie] Cookies missing security flags
...
```

> 📸 **Tip:** add screenshots of your own scans to a `docs/` folder and link them here.

## 📊 Scoring and exit codes

Every target starts at **100** and loses points per finding:

| Severity | Penalty |
|---|---|
| CRITICAL | -25 |
| HIGH | -15 |
| MEDIUM | -8 |
| LOW | -3 |
| INFO | 0 |

Grades: **A** ≥ 90, **B** ≥ 80, **C** ≥ 65, **D** ≥ 50, **F** below 50.

| Exit code | Meaning |
|---|---|
| `0` | Scan completed, nothing at or above the `--fail-on` threshold |
| `1` | At least one finding at or above the threshold |
| `2` | No target could be scanned (bad input or connection errors) |

## 🔁 Using it in CI/CD

Fail a pipeline when a deployed staging site has serious misconfigurations:

```yaml
# .github/workflows/security-headers.yml
name: Header and CORS audit
on: [push, workflow_dispatch]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: python scanner.py https://your-staging-site.example --fail-on HIGH --markdown report.md
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: scan-report
          path: report.md
```

## 📁 Project structure

```text
web-security-scanner/
├── scanner.py          # main CLI tool (header, cookie and CORS checks, reporting)
├── demo_server.py      # local insecure / hardened server for safe testing
├── requirements.txt    # Python dependencies (requests)
├── README.md
├── LICENSE
└── .gitignore
```

## ⚠️ Limitations

- Checks only the **final URL** of a single request. It does **not crawl**, so headers on other pages or API routes may differ.
- CSP analysis is a **heuristic**; it flags common unsafe patterns, not every possible bypass.
- Cookie checks cannot tell which cookie is the session cookie, so all cookies are held to the same standard.
- CORS results depend on how the server behaves for the specific URL tested; test your API endpoints directly for accurate results.
- A passing score does **not** mean a site is secure. This is a configuration audit, not a penetration test.

## 🗺 Roadmap

- [ ] Crawl same-origin links and scan multiple pages
- [ ] TLS checks (protocol versions, certificate expiry)
- [ ] `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy` checks
- [ ] HTML report output
- [ ] Unit tests and a GitHub Actions workflow for the scanner itself

## 🛡 Responsible use

This tool sends a small number of ordinary `GET` and `OPTIONS` requests (about 7 per target) with a clearly identifiable `User-Agent`. It does not exploit vulnerabilities or attempt to access data.

- Only scan systems you **own** or have **explicit written permission** to test.
- Unauthorised scanning may be illegal in your jurisdiction.
- The author accepts no liability for misuse.

## 📚 References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP Top 10: A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [PortSwigger Web Security Academy: CORS](https://portswigger.net/web-security/cors)
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

## 📄 License

Released under the [MIT License](LICENSE).

## 👤 Author

**vaibhav-s-gh**: built for the IBM Cybersecurity Bootcamp.
