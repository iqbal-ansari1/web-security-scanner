#!/usr/bin/env python3
"""
Automated Web Scanner
=====================
Audits a website for missing or weak HTTP security headers, insecure cookie
flags, and CORS misconfigurations.

Only scan systems you own or have explicit written permission to test.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3
from requests.exceptions import RequestException

__version__ = "1.0.0"

USER_AGENT = f"WebSecScanner/{__version__} (educational security audit)"
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
PENALTY = {"INFO": 0, "LOW": 3, "MEDIUM": 8, "HIGH": 15, "CRITICAL": 25}
COLORS = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "INFO": "\033[37m",
    "PASS": "\033[32m",
    "RESET": "\033[0m",
}
EVIL_ORIGIN = "https://evil-attacker.example"


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    category: str  # header | cookie | cors
    severity: str
    title: str
    detail: str
    fix: str


@dataclass
class Report:
    target: str
    final_url: str = ""
    status_code: int = 0
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    findings: list[Finding] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)

    def fail(self, category, severity, title, detail, fix):
        self.findings.append(Finding(category, severity, title, detail, fix))

    def ok(self, message):
        self.passed.append(message)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(PENALTY[f.severity] for f in self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        for cutoff, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
            if s >= cutoff:
                return letter
        return "F"


# --------------------------------------------------------------------------- #
# HTTP helper
# --------------------------------------------------------------------------- #
def send(url, method="GET", headers=None, timeout=10, verify=True):
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    return requests.request(
        method, url, headers=hdrs, timeout=timeout, verify=verify, allow_redirects=True
    )


# --------------------------------------------------------------------------- #
# Check 1: security headers
# --------------------------------------------------------------------------- #
def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def check_security_headers(resp, report: Report) -> None:
    h = resp.headers
    is_https = resp.url.lower().startswith("https://")

    # --- Transport security -------------------------------------------------
    if not is_https:
        report.fail(
            "header", "HIGH", "Site served over plain HTTP",
            "Traffic can be read or modified by anyone on the network path.",
            "Serve the site over HTTPS and redirect all HTTP traffic to it.",
        )
    else:
        hsts = h.get("Strict-Transport-Security")
        if not hsts:
            report.fail(
                "header", "MEDIUM", "Missing Strict-Transport-Security (HSTS)",
                "Browsers are not told to always use HTTPS, which leaves room for SSL-stripping.",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains",
            )
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15552000:  # 180 days
                report.fail(
                    "header", "LOW", "Weak HSTS max-age",
                    f"max-age is {age} seconds (less than 180 days).",
                    "Use max-age=31536000 (1 year) or more.",
                )
            else:
                report.ok("Strict-Transport-Security is set with a long max-age")

    # --- Content-Security-Policy -------------------------------------------
    csp = h.get("Content-Security-Policy")
    csp_dirs = parse_csp(csp) if csp else {}
    if not csp:
        report.fail(
            "header", "MEDIUM", "Missing Content-Security-Policy",
            "No CSP means the browser has no second line of defence against XSS.",
            "Start with: Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
        )
    else:
        script_src = csp_dirs.get("script-src", csp_dirs.get("default-src"))
        problems = []
        if script_src is None:
            problems.append("no script-src or default-src directive")
        else:
            strict = any(
                t.startswith(("'nonce-", "'sha")) or t == "'strict-dynamic'"
                for t in script_src
            )
            if "'unsafe-inline'" in script_src and not strict:
                problems.append("'unsafe-inline' allows inline scripts")
            if "'unsafe-eval'" in script_src:
                problems.append("'unsafe-eval' allows eval()")
            if "*" in script_src:
                problems.append("wildcard (*) allows scripts from any host")
        if problems:
            report.fail(
                "header", "MEDIUM", "Weak Content-Security-Policy",
                "; ".join(problems),
                "Remove unsafe sources; use nonces or hashes for inline scripts.",
            )
        else:
            report.ok("Content-Security-Policy has no obviously unsafe script sources")

    # --- Clickjacking -------------------------------------------------------
    xfo = h.get("X-Frame-Options", "").strip().upper()
    if "frame-ancestors" in csp_dirs or xfo in ("DENY", "SAMEORIGIN"):
        report.ok("Clickjacking protection present (X-Frame-Options or frame-ancestors)")
    elif xfo:
        report.fail(
            "header", "LOW", "Invalid X-Frame-Options value",
            f"Value '{xfo}' is obsolete or not recognised by modern browsers.",
            "Use X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
        )
    else:
        report.fail(
            "header", "MEDIUM", "Missing clickjacking protection",
            "Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed.",
            "X-Frame-Options: DENY  (or CSP: frame-ancestors 'none')",
        )

    # --- MIME sniffing ------------------------------------------------------
    if h.get("X-Content-Type-Options", "").strip().lower() == "nosniff":
        report.ok("X-Content-Type-Options: nosniff")
    else:
        report.fail(
            "header", "LOW", "Missing X-Content-Type-Options",
            "Browsers may MIME-sniff responses and execute content as a different type.",
            "X-Content-Type-Options: nosniff",
        )

    # --- Referrer-Policy ----------------------------------------------------
    rp = h.get("Referrer-Policy")
    if not rp:
        report.fail(
            "header", "LOW", "Missing Referrer-Policy",
            "Full URLs (possibly with tokens in the query string) may leak to other sites.",
            "Referrer-Policy: strict-origin-when-cross-origin",
        )
    elif rp.split(",")[-1].strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        report.fail(
            "header", "LOW", "Weak Referrer-Policy",
            f"'{rp}' still leaks full URLs to third parties.",
            "Referrer-Policy: strict-origin-when-cross-origin",
        )
    else:
        report.ok("Referrer-Policy is set")

    # --- Permissions-Policy -------------------------------------------------
    if h.get("Permissions-Policy"):
        report.ok("Permissions-Policy is set")
    else:
        report.fail(
            "header", "LOW", "Missing Permissions-Policy",
            "Powerful browser features (camera, mic, geolocation) are not explicitly restricted.",
            "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        )

    # --- Information disclosure --------------------------------------------
    server = h.get("Server", "")
    if re.search(r"\d", server):
        report.fail(
            "header", "LOW", "Server header discloses version",
            f"Server: {server}",
            "Strip or genericise the Server header at the web server / proxy.",
        )
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        if name in h:
            report.fail(
                "header", "LOW", f"{name} header present",
                f"{name}: {h[name]} reveals the technology stack.",
                f"Remove the {name} header.",
            )


# --------------------------------------------------------------------------- #
# Check 2: cookie flags
# --------------------------------------------------------------------------- #
def check_cookies(resp, report: Report) -> None:
    try:
        raw_cookies = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        raw_cookies = [resp.headers["Set-Cookie"]] if "Set-Cookie" in resp.headers else []
    if not raw_cookies:
        return

    is_https = resp.url.lower().startswith("https://")
    issues, secure_missing = [], False
    for cookie in raw_cookies:
        parts = [p.strip() for p in cookie.split(";")]
        name = parts[0].split("=")[0]
        attrs = [p.lower() for p in parts[1:]]
        missing = []
        if is_https and "secure" not in attrs:
            missing.append("Secure")
            secure_missing = True
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if not any(a.startswith("samesite=") for a in attrs):
            missing.append("SameSite")
        if missing:
            issues.append(f"{name}: missing {', '.join(missing)}")

    if issues:
        report.fail(
            "cookie", "MEDIUM" if secure_missing else "LOW",
            "Cookies missing security flags", "; ".join(issues),
            "Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax",
        )
    else:
        report.ok("All cookies set Secure/HttpOnly/SameSite")


# --------------------------------------------------------------------------- #
# Check 3: CORS
# --------------------------------------------------------------------------- #
def check_cors(url: str, report: Report, timeout: int, verify: bool) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or ""

    # (label, Origin header to send, severity if credentials are allowed)
    tests = [
        ("Arbitrary origin reflected", EVIL_ORIGIN, "CRITICAL"),
        ("'null' origin trusted", "null", "HIGH"),
        ("Origin suffix-match bypass", f"https://{host}.evil-attacker.example", "HIGH"),
        ("Origin prefix/substring bypass", f"https://not{host}", "HIGH"),
    ]
    if parsed.scheme == "https":
        tests.append(("Insecure (http) origin trusted", f"http://{host}", "MEDIUM"))
    no_creds_severity = {"CRITICAL": "MEDIUM", "HIGH": "LOW", "MEDIUM": "LOW"}

    findings_before = len(report.findings)
    saw_cors_headers = wildcard_reported = vary_missing = False

    for label, origin, severity in tests:
        try:
            r = send(url, headers={"Origin": origin}, timeout=timeout, verify=verify)
        except RequestException as exc:
            report.fail("cors", "INFO", f"CORS probe failed: {label}", str(exc), "Retry the scan.")
            continue

        acao = r.headers.get("Access-Control-Allow-Origin")
        creds = r.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
        if acao:
            saw_cors_headers = True

        if acao == origin:
            if "origin" not in r.headers.get("Vary", "").lower():
                vary_missing = True
            if creds:
                report.fail(
                    "cors", severity, f"{label} (with credentials)",
                    f"Origin '{origin}' was echoed in Access-Control-Allow-Origin and "
                    "Access-Control-Allow-Credentials is true. A malicious site could read "
                    "authenticated responses.",
                    "Validate Origin against an exact allow-list; never reflect it blindly.",
                )
            else:
                report.fail(
                    "cors", no_creds_severity[severity], label,
                    f"Origin '{origin}' was echoed in Access-Control-Allow-Origin "
                    "(credentials not allowed).",
                    "Validate Origin against an exact allow-list; never reflect it blindly.",
                )
        elif acao == "*" and not wildcard_reported:
            wildcard_reported = True
            if creds:
                report.fail(
                    "cors", "MEDIUM", "Wildcard origin combined with credentials",
                    "Access-Control-Allow-Origin: * with Allow-Credentials: true is an "
                    "invalid, confused configuration.",
                    "Use an explicit origin allow-list if credentials are required.",
                )
            else:
                report.fail(
                    "cors", "LOW", "Wildcard CORS policy",
                    "Access-Control-Allow-Origin: * lets any website read responses.",
                    "Acceptable only for fully public data; otherwise use an allow-list.",
                )

    if vary_missing:
        report.fail(
            "cors", "LOW", "Dynamic ACAO without 'Vary: Origin'",
            "Caches may serve one origin's CORS headers to another origin.",
            "Add 'Vary: Origin' whenever the ACAO value depends on the request.",
        )

    # Preflight check
    try:
        pf = send(
            url, method="OPTIONS", timeout=timeout, verify=verify,
            headers={
                "Origin": EVIL_ORIGIN,
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "authorization, content-type",
            },
        )
        pf_acao = pf.headers.get("Access-Control-Allow-Origin")
        if pf_acao:
            saw_cors_headers = True
        if pf_acao in (EVIL_ORIGIN, "*"):
            methods = pf.headers.get("Access-Control-Allow-Methods", "").upper()
            risky = [m for m in ("PUT", "PATCH", "DELETE") if m in methods]
            if risky:
                report.fail(
                    "cors", "MEDIUM", "Preflight allows state-changing methods from untrusted origin",
                    f"Methods allowed for {EVIL_ORIGIN}: {', '.join(risky)}.",
                    "Restrict Access-Control-Allow-Methods and the allowed origins.",
                )
    except RequestException:
        pass  # many servers simply refuse OPTIONS; not a finding

    if not saw_cors_headers:
        report.ok("No CORS headers returned to cross-origin requests (same-origin policy applies)")
    elif len(report.findings) == findings_before:
        report.ok("CORS policy rejected all untrusted test origins")


# --------------------------------------------------------------------------- #
# Orchestration and output
# --------------------------------------------------------------------------- #
def normalize_url(raw: str) -> str:
    raw = raw.strip()
    return raw if re.match(r"^https?://", raw, re.I) else "https://" + raw


def scan(url: str, timeout: int, verify: bool) -> Report:
    report = Report(target=url)
    resp = send(url, timeout=timeout, verify=verify)
    report.final_url, report.status_code = resp.url, resp.status_code
    check_security_headers(resp, report)
    check_cookies(resp, report)
    check_cors(resp.url, report, timeout, verify)
    return report


def print_report(report: Report, color: bool) -> None:
    def paint(text, key):
        return f"{COLORS[key]}{text}{COLORS['RESET']}" if color else text

    print("=" * 70)
    print(f"Target : {report.target}")
    if report.final_url != report.target:
        print(f"Final  : {report.final_url}")
    print(f"Status : HTTP {report.status_code}   Scanned: {report.scanned_at}")
    print(f"Score  : {report.score}/100   Grade: {report.grade}")
    print("=" * 70)

    findings = sorted(report.findings, key=lambda f: -SEVERITIES.index(f.severity))
    for f in findings:
        print(f"{paint(f'[{f.severity}]', f.severity):<18} [{f.category}] {f.title}")
        print(f"    Why : {f.detail}")
        print(f"    Fix : {f.fix}")
    for msg in report.passed:
        print(f"{paint('[PASS]', 'PASS')}   {msg}")
    print()


def to_markdown(reports: list[Report]) -> str:
    lines = ["# Web Security Scan Report", ""]
    for r in reports:
        lines += [
            f"## {r.target}", "",
            f"- **Final URL:** {r.final_url}",
            f"- **HTTP status:** {r.status_code}",
            f"- **Scanned (UTC):** {r.scanned_at}",
            f"- **Score:** {r.score}/100 (Grade {r.grade})", "",
            "| Severity | Category | Issue | Details | Recommended fix |",
            "|---|---|---|---|---|",
        ]
        for f in sorted(r.findings, key=lambda x: -SEVERITIES.index(x.severity)):
            row = [f.severity, f.category, f.title, f.detail, f"`{f.fix}`"]
            lines.append("| " + " | ".join(c.replace("|", "\\|") for c in row) + " |")
        if r.passed:
            lines += ["", "**Passed checks:**", ""] + [f"- {p}" for p in r.passed]
        lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit websites for missing security headers and CORS misconfigurations. "
        "Only scan systems you own or have written permission to test."
    )
    p.add_argument("urls", nargs="*", help="Target URL(s), e.g. https://example.com")
    p.add_argument("-f", "--file", help="Text file with one target URL per line")
    p.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default 10)")
    p.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    p.add_argument("--json", metavar="PATH", help="Write results as JSON to PATH")
    p.add_argument("--markdown", metavar="PATH", help="Write results as a Markdown report to PATH")
    p.add_argument("--fail-on", choices=SEVERITIES + ["NONE"], default="HIGH",
                   help="Exit with code 1 if any finding is at or above this severity (default HIGH)")
    p.add_argument("--no-color", action="store_true", help="Disable coloured output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    targets = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not targets:
        build_parser().print_usage(sys.stderr)
        print("error: provide at least one URL or --file", file=sys.stderr)
        return 2

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print("[!] Only scan systems you own or have explicit permission to test.\n", file=sys.stderr)
    color = sys.stdout.isatty() and not args.no_color

    reports, had_error = [], False
    for raw in targets:
        url = normalize_url(raw)
        try:
            report = scan(url, args.timeout, verify=not args.insecure)
        except RequestException as exc:
            print(f"[ERROR] Could not scan {url}: {exc}\n", file=sys.stderr)
            had_error = True
            continue
        reports.append(report)
        print_report(report, color)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([asdict(r) | {"score": r.score, "grade": r.grade} for r in reports], fh, indent=2)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(reports))

    if had_error and not reports:
        return 2
    if args.fail_on != "NONE":
        threshold = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f.severity) >= threshold for r in reports for f in r.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
