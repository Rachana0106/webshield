import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from http.cookies import SimpleCookie

import requests
from bs4 import BeautifulSoup

from .network_guard import normalize_and_validate_url
from .knowledge import FINDING_HELP, GLOSSARY
from .scoring import calculate_scores


MAX_BODY_BYTES = 2_000_000
MAX_REDIRECTS = 5
USER_AGENT = "WebShield/2.0 Defensive Web Security Auditor"


def make_finding(
    code,
    category,
    title,
    severity,
    confidence,
    status,
    technical_description,
    recommendation,
    evidence="",
    references=None,
):
    help_data = FINDING_HELP.get(code, {})
    return {
        "code": code,
        "category": category,
        "title": title,
        "friendly_title": help_data.get("friendly_title", title),
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "technical_description": technical_description,
        "what_it_means": help_data.get("what_it_means", technical_description),
        "why_care": help_data.get("why_care", "Review this finding in the context of how the website is designed."),
        "does_it_mean_hacked": help_data.get(
            "does_it_mean_hacked",
            "No conclusion about compromise can be made from this observation alone."
        ),
        "term": help_data.get("term", ""),
        "recommendation": recommendation,
        "evidence": evidence,
        "references": references or [],
    }


def safe_fetch(start_url):
    """
    Follow redirects manually so each destination is validated before WebShield requests it.
    Response body is capped to avoid downloading unexpectedly large content.
    """
    session = requests.Session()
    current = normalize_and_validate_url(start_url)
    history = []

    for _ in range(MAX_REDIRECTS + 1):
        response = session.get(
            current,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
            timeout=(10, 20),
            allow_redirects=False,
            stream=True,
        )

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("location")
            response.close()
            if not location:
                raise ValueError("The website returned a redirect without a destination.")
            next_url = urljoin(current, location)
            next_url = normalize_and_validate_url(next_url)
            history.append(current)
            current = next_url
            continue

        content_type = response.headers.get("content-type", "")
        body = bytearray()

        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            remaining = MAX_BODY_BYTES - len(body)
            if remaining <= 0:
                break
            body.extend(chunk[:remaining])

        response.close()
        encoding = response.encoding or "utf-8"
        try:
            text = body.decode(encoding, errors="replace")
        except LookupError:
            text = body.decode("utf-8", errors="replace")

        return {
            "url": current,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_type": content_type,
            "text": text,
            "redirect_count": len(history),
            "truncated": len(body) >= MAX_BODY_BYTES,
        }

    raise ValueError(f"Too many redirects. WebShield follows at most {MAX_REDIRECTS} redirects.")


def check_tls(hostname: str, port: int = 443):
    result = {
        "enabled": False,
        "valid": False,
        "issuer": "",
        "subject": "",
        "expires_at": "",
        "days_remaining": None,
        "protocol": "",
        "cipher": "",
        "error": "",
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["enabled"] = True
                result["valid"] = True
                result["protocol"] = ssock.version() or ""
                cipher = ssock.cipher()
                result["cipher"] = cipher[0] if cipher else ""

                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                result["issuer"] = issuer.get("organizationName", "") or issuer.get("commonName", "")
                result["subject"] = subject.get("commonName", "")

                expires = cert.get("notAfter")
                if expires:
                    dt = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["expires_at"] = dt.isoformat()
                    result["days_remaining"] = (dt - datetime.now(timezone.utc)).days
    except Exception as exc:
        result["error"] = str(exc)

    return result


def parse_csp(value):
    directives = {}
    for section in value.split(";"):
        section = section.strip()
        if not section:
            continue
        parts = section.split()
        directives[parts[0].lower()] = parts[1:]
    return directives


def parse_cookie_headers(headers):
    """
    requests collapses repeated Set-Cookie headers on some adapters. We therefore parse
    the combined value conservatively and treat results as observed indicators.
    """
    raw = headers.get("set-cookie", "")
    if not raw:
        return []

    pieces = re.split(r",(?=\s*[^;,=\s]+=[^;,]*)", raw)
    output = []
    for piece in pieces[:30]:
        first = piece.split(";", 1)[0].strip()
        if "=" not in first:
            continue
        name = first.split("=", 1)[0].strip()
        lower = piece.lower()
        same_site_match = re.search(r"(?i)samesite\s*=\s*(lax|strict|none)", piece)
        output.append({
            "name": name,
            "secure": bool(re.search(r"(?i)(^|;)\s*secure(?:;|$)", piece)),
            "httponly": bool(re.search(r"(?i)(^|;)\s*httponly(?:;|$)", piece)),
            "samesite": same_site_match.group(1).capitalize() if same_site_match else "",
        })
    return output


def classify_form(form):
    has_password = form.find("input", {"type": re.compile("^password$", re.I)}) is not None
    has_file = form.find("input", {"type": re.compile("^file$", re.I)}) is not None
    text = " ".join(
        [(form.get("id") or ""), (form.get("class") and " ".join(form.get("class")) or ""),
         form.get_text(" ", strip=True)]
    ).lower()

    if has_password:
        return "Login / authentication form"
    if has_file:
        return "File upload form"
    if any(k in text for k in ["contact", "message", "email", "name"]):
        return "Contact / message form"
    if any(k in text for k in ["search", "query"]):
        return "Search form"
    return "General form"


def detect_technologies(headers, soup, html):
    detected = set()
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")

    if server:
        detected.add(server)
    if powered:
        detected.add(powered)

    generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if generator and generator.get("content"):
        detected.add(generator["content"])

    signatures = {
        "React": ["react", "_next/static", "__next_data__"],
        "Next.js": ["_next/static", "__next_data__"],
        "Vue": ["vue", "__vue__"],
        "Angular": ["ng-version", "angular"],
        "Bootstrap": ["bootstrap.min.css", "bootstrap.bundle"],
        "Tailwind CSS": ["tailwind"],
        "WordPress": ["wp-content", "wp-includes"],
        "Vercel": ["vercel"],
    }

    lower = html.lower()
    for tech, markers in signatures.items():
        if any(marker.lower() in lower for marker in markers):
            detected.add(tech)

    return sorted(detected)



def build_cia_summary(findings):
    """
    CIA is reported qualitatively because a passive public-page scan cannot
    truthfully quantify confidentiality, integrity, or availability as percentages.
    """
    mapping = {
        "Confidentiality": [],
        "Integrity": [],
        "Availability": [],
    }

    for f in findings:
        if f.get("status") not in {
            "Confirmed Configuration Finding",
            "Probable Finding",
            "Potential Concern",
        }:
            continue

        category = f.get("category")
        title = f.get("friendly_title") or f.get("title")

        if category in {
            "Transport Security", "Cookie Security",
            "Cross-Origin Security", "Information Exposure"
        }:
            mapping["Confidentiality"].append(title)

        if category in {
            "Transport Security", "Browser Security",
            "Cookie Security", "Form Security",
            "Third-Party Resources", "Client-Side Review"
        }:
            mapping["Integrity"].append(title)

    def result_for(name):
        items = list(dict.fromkeys(mapping[name]))[:4]
        if name == "Availability":
            return {
                "status": "Not meaningfully assessed",
                "level": "Not Assessed",
                "explanation": (
                    "WebShield does not perform denial-of-service, capacity, uptime, redundancy, "
                    "or infrastructure resilience testing, so it does not score Availability."
                ),
                "related_findings": [],
            }

        if items:
            return {
                "status": "Potential impact indicated",
                "level": "Review Recommended",
                "explanation": (
                    f"Some observed findings may affect {name.lower()} in certain attack scenarios. "
                    "This is not proof that the CIA property has been compromised."
                ),
                "related_findings": items,
            }

        return {
            "status": "No issue observed in checked signals",
            "level": "No Observable Issue",
            "explanation": (
                f"WebShield did not observe a checked finding clearly related to {name.lower()}. "
                "This does not prove complete protection."
            ),
            "related_findings": [],
        }

    return {
        "Confidentiality": result_for("Confidentiality"),
        "Integrity": result_for("Integrity"),
        "Availability": result_for("Availability"),
    }

def build_hackability_summary(findings, score):
    confirmed_high = [
        f for f in findings
        if f.get("status") == "Confirmed Configuration Finding"
        and f.get("severity") in {"Critical", "High"}
    ]
    confirmed_medium = [
        f for f in findings
        if f.get("status") == "Confirmed Configuration Finding"
        and f.get("severity") == "Medium"
    ]

    if confirmed_high:
        level = "Important configuration weakness observed"
        message = (
            "At least one important configuration weakness was directly observed. "
            "It should be fixed, but WebShield has not demonstrated that the website can be compromised."
        )
    elif confirmed_medium:
        level = "Hardening gaps observed"
        message = (
            "Some browser or application hardening controls should be improved. "
            "These findings may increase attack surface in certain situations, but they are not proof of exploitability."
        )
    else:
        level = "No high-risk configuration issue observed"
        message = (
            "The passive checks did not reveal an important confirmed configuration weakness. "
            "Application bugs, access-control flaws, authentication problems, dependency vulnerabilities, "
            "server-side issues and business-logic flaws may still exist outside this scan."
        )

    return {
        "level": level,
        "message": message,
        "answer": (
            "WebShield cannot determine whether this website is hackable from passive configuration checks alone."
        )
    }

def build_ai_remediation_prompt(result):
    actionable = [
        f for f in result.get("findings", [])
        if f.get("status") == "Confirmed Configuration Finding"
        and f.get("severity") != "Info"
    ]

    lines = [
        "I own or am authorized to maintain this website:",
        result.get("final_url", ""),
        "",
        "Please help me harden it safely without breaking existing functionality, layout, forms, APIs, third-party integrations, analytics, deployment, or user experience.",
        "",
        "Important rules:",
        "- Preserve all current working features.",
        "- Do not remove functionality just to improve a security score.",
        "- Prefer standards-based fixes with the smallest safe change.",
        "- Explain every change before giving code.",
        "- If a security header could break scripts, fonts, images, forms, APIs, embeds, or analytics, tailor it to the actual site instead of using an overly strict generic policy.",
        "- Do not claim the site is fully secure after these fixes.",
        "- Keep confidentiality, integrity and availability in mind.",
        "",
        "WebShield findings to address:"
    ]

    if not actionable:
        lines.append("- No confirmed actionable configuration finding was recorded.")
    else:
        for f in actionable:
            lines.append(
                f"- [{f.get('severity')}] {f.get('title')}: {f.get('recommendation')}"
            )

    lines.extend([
        "",
        "For each item, give me:",
        "1. What should change",
        "2. Why it improves security",
        "3. Exact code/configuration for my stack",
        "4. What could break",
        "5. How to test the change",
        "6. How to roll it back if needed",
        "",
        "Before giving final code, ask me what framework/hosting setup I use if that information is necessary."
    ])

    return "\n".join(lines)


def analyze_website(raw_url: str):
    fetched = safe_fetch(raw_url)
    final_url = fetched["url"]
    parsed = urlparse(final_url)
    html = fetched["text"]
    soup = BeautifulSoup(html, "html.parser")
    response_headers_original = fetched["headers"]
    headers = {k.lower(): v for k, v in response_headers_original.items()}
    findings = []

    # ---------------- Transport security ----------------
    uses_https = parsed.scheme == "https"
    tls = check_tls(parsed.hostname, parsed.port or 443) if uses_https else {
        "enabled": False, "valid": False, "issuer": "", "subject": "",
        "expires_at": "", "days_remaining": None, "protocol": "", "cipher": "",
        "error": "The final URL is not using HTTPS."
    }

    if not uses_https:
        findings.append(make_finding(
            "http_site", "Transport Security",
            "Website is not using HTTPS", "High", "High",
            "Confirmed Configuration Finding",
            "The final URL uses HTTP rather than HTTPS.",
            "Enable HTTPS and redirect HTTP requests to HTTPS.",
            final_url,
        ))
    elif not tls["valid"]:
        findings.append(make_finding(
            "tls_invalid", "Transport Security",
            "TLS certificate validation failed", "High", "High",
            "Confirmed Configuration Finding",
            "WebShield could not validate the site's TLS certificate.",
            "Check certificate expiry, hostname coverage and trust-chain configuration.",
            tls.get("error", ""),
        ))
    elif tls["days_remaining"] is not None and tls["days_remaining"] < 30:
        findings.append(make_finding(
            "tls_expiring", "Transport Security",
            "TLS certificate expires soon", "Medium", "High",
            "Confirmed Configuration Finding",
            f"The certificate has approximately {tls['days_remaining']} day(s) remaining.",
            "Renew the TLS certificate before it expires.",
            tls.get("expires_at", ""),
        ))

    # ---------------- Security headers / CSP quality ----------------
    security_headers = []
    core_headers = [
        ("content-security-policy", "Content-Security-Policy"),
        ("strict-transport-security", "Strict-Transport-Security"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
        ("x-frame-options", "X-Frame-Options"),
    ]

    for key, label in core_headers:
        security_headers.append({
            "name": label,
            "present": key in headers,
            "value": headers.get(key, ""),
        })

    csp_value = headers.get("content-security-policy", "")
    csp = parse_csp(csp_value) if csp_value else {}

    if not csp_value:
        findings.append(make_finding(
            "missing_csp", "Browser Security",
            "Content-Security-Policy header is missing", "Medium", "High",
            "Confirmed Configuration Finding",
            "The HTTP response does not contain a Content-Security-Policy header.",
            "Add a CSP that matches the resources the application genuinely needs."
        ))
    else:
        risky = []
        script_sources = csp.get("script-src", csp.get("default-src", []))
        if "'unsafe-inline'" in script_sources:
            risky.append("'unsafe-inline' in script-src")
        if "'unsafe-eval'" in script_sources:
            risky.append("'unsafe-eval' in script-src")
        if "*" in script_sources:
            risky.append("wildcard * in script-src")
        if not csp.get("default-src") and not csp.get("script-src"):
            risky.append("no default-src or script-src restriction")
        if risky:
            findings.append(make_finding(
                "weak_csp", "Browser Security",
                "Content-Security-Policy contains permissive script settings",
                "Medium", "High", "Confirmed Configuration Finding",
                "The CSP exists, but WebShield found potentially permissive script directives.",
                "Review the CSP and remove permissive directives where the application can work without them.",
                "; ".join(risky)
            ))

    nosniff = headers.get("x-content-type-options", "").strip().lower()
    if nosniff != "nosniff":
        findings.append(make_finding(
            "missing_nosniff", "Browser Security",
            "X-Content-Type-Options is missing or not set to nosniff",
            "Low", "High", "Confirmed Configuration Finding",
            "The response does not explicitly set X-Content-Type-Options: nosniff.",
            "Set X-Content-Type-Options to nosniff."
        ))

    if "referrer-policy" not in headers:
        findings.append(make_finding(
            "missing_referrer", "Browser Security",
            "Referrer-Policy is missing", "Low", "High",
            "Confirmed Configuration Finding",
            "No Referrer-Policy header was detected.",
            "Choose an appropriate policy such as strict-origin-when-cross-origin."
        ))

    if "permissions-policy" not in headers:
        findings.append(make_finding(
            "missing_permissions", "Browser Security",
            "Permissions-Policy is missing", "Low", "High",
            "Confirmed Configuration Finding",
            "No Permissions-Policy header was detected.",
            "Restrict unnecessary browser features with Permissions-Policy."
        ))

    frame_ancestors = csp.get("frame-ancestors", []) if csp else []
    xfo = headers.get("x-frame-options", "").strip().lower()
    frame_protected = bool(frame_ancestors) or xfo in {"deny", "sameorigin"} or xfo.startswith("allow-from")
    if not frame_protected:
        findings.append(make_finding(
            "clickjacking", "Browser Security",
            "Clickjacking protection is not evident", "Medium", "High",
            "Confirmed Configuration Finding",
            "Neither a CSP frame-ancestors directive nor a recognized X-Frame-Options value was detected.",
            "Use CSP frame-ancestors and/or X-Frame-Options where appropriate."
        ))

    # HSTS only matters on HTTPS.
    if uses_https and "strict-transport-security" not in headers:
        findings.append(make_finding(
            "missing_referrer", "Transport Security",
            "Strict-Transport-Security is missing", "Low", "High",
            "Confirmed Configuration Finding",
            "The HTTPS response does not contain an HSTS header.",
            "Consider enabling HSTS after confirming the website is fully available over HTTPS."
        ))

    # ---------------- Cookies ----------------
    cookies = parse_cookie_headers(headers)
    for cookie in cookies:
        if uses_https and not cookie["secure"]:
            findings.append(make_finding(
                "cookie_secure", "Cookie Security",
                f"Cookie '{cookie['name']}' is missing Secure",
                "Medium", "High", "Confirmed Configuration Finding",
                "The observed Set-Cookie value does not include Secure.",
                "Add Secure to sensitive cookies that should travel only over HTTPS.",
                cookie["name"],
            ))
        if not cookie["httponly"]:
            findings.append(make_finding(
                "cookie_httponly", "Cookie Security",
                f"Cookie '{cookie['name']}' is missing HttpOnly",
                "Low", "Medium", "Potential Concern",
                "The observed Set-Cookie value does not include HttpOnly.",
                "If JavaScript does not need this cookie, consider adding HttpOnly.",
                cookie["name"],
            ))
        if not cookie["samesite"]:
            findings.append(make_finding(
                "cookie_samesite", "Cookie Security",
                f"Cookie '{cookie['name']}' has no explicit SameSite value",
                "Low", "Medium", "Potential Concern",
                "The observed Set-Cookie value does not include SameSite.",
                "Choose Lax, Strict or None according to the application's legitimate cross-site requirements.",
                cookie["name"],
            ))
        elif cookie["samesite"].lower() == "none" and not cookie["secure"]:
            findings.append(make_finding(
                "cookie_secure", "Cookie Security",
                f"Cookie '{cookie['name']}' uses SameSite=None without Secure",
                "Medium", "High", "Confirmed Configuration Finding",
                "SameSite=None cookies should also use Secure in modern browsers.",
                "Add the Secure attribute when SameSite=None is required.",
                cookie["name"],
            ))

    # ---------------- Forms ----------------
    forms = []
    for idx, form in enumerate(soup.find_all("form")[:50], start=1):
        action = form.get("action") or final_url
        action_url = urljoin(final_url, action)
        method = (form.get("method") or "GET").upper()
        has_password = form.find("input", {"type": re.compile("^password$", re.I)}) is not None
        hidden_names = [
            (inp.get("name") or "").lower()
            for inp in form.find_all("input", {"type": "hidden"})
        ]
        csrf_hint = any(
            token in name
            for name in hidden_names
            for token in ["csrf", "xsrf", "authenticity_token", "requestverificationtoken"]
        )

        form_type = classify_form(form)
        forms.append({
            "index": idx,
            "type": form_type,
            "action": action_url,
            "method": method,
            "password_field": has_password,
            "csrf_indicator": csrf_hint,
        })

        action_scheme = urlparse(action_url).scheme
        if has_password and action_scheme != "https":
            findings.append(make_finding(
                "http_site", "Form Security",
                f"Password form #{idx} submits without HTTPS",
                "High", "High", "Confirmed Configuration Finding",
                "A form containing a password field appears to submit to a non-HTTPS destination.",
                "Submit passwords only to HTTPS destinations.",
                action_url,
            ))

        if method == "POST" and not csrf_hint:
            findings.append(make_finding(
                "csrf_hint", "Form Security",
                f"POST form #{idx} has no obvious anti-CSRF token",
                "Info", "Low", "Manual Review Required",
                "No hidden field with a common anti-CSRF token name was visible in the HTML.",
                "Verify the framework/server-side CSRF protection manually.",
                action_url,
            ))

    # ---------------- CORS ----------------
    cors = {
        "allow_origin": headers.get("access-control-allow-origin", ""),
        "allow_credentials": headers.get("access-control-allow-credentials", ""),
        "vary": headers.get("vary", ""),
    }

    if cors["allow_origin"] == "*":
        if cors["allow_credentials"].lower() == "true":
            findings.append(make_finding(
                "cors_credentials_wildcard", "Cross-Origin Security",
                "Broad CORS origin advertised with credentials",
                "Medium", "High", "Confirmed Configuration Finding",
                "The response includes Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.",
                "Review whether cross-origin credentialed access is intended and configure explicit trusted origins.",
                "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true"
            ))
        else:
            findings.append(make_finding(
                "cors_wildcard", "Cross-Origin Security",
                "CORS allows any origin for this response",
                "Info", "High", "Informational",
                "The response includes Access-Control-Allow-Origin: *.",
                "If the response contains only public data, this may be intentional. Otherwise use an explicit origin policy.",
                "Access-Control-Allow-Origin: *"
            ))

    # ---------------- Resources / mixed content / SRI ----------------
    external_domains = set()
    mixed_content = []
    third_party_scripts = []

    for tag_name, attr in [
        ("script", "src"), ("img", "src"), ("iframe", "src"),
        ("link", "href"), ("audio", "src"), ("video", "src")
    ]:
        for tag in soup.find_all(tag_name)[:500]:
            value = tag.get(attr)
            if not value:
                continue
            absolute = urljoin(final_url, value)
            p = urlparse(absolute)

            if p.hostname and p.hostname.lower() != (parsed.hostname or "").lower():
                external_domains.add(p.hostname.lower())

            if uses_https and p.scheme == "http":
                mixed_content.append(absolute)
                findings.append(make_finding(
                    "mixed_content", "Third-Party Resources",
                    "Mixed-content resource detected", "Medium", "High",
                    "Confirmed Configuration Finding",
                    "An HTTPS page references a resource over plain HTTP.",
                    "Load the resource over HTTPS or remove it.",
                    absolute,
                ))

            if tag_name == "script" and p.hostname and p.hostname.lower() != (parsed.hostname or "").lower():
                has_integrity = bool(tag.get("integrity"))
                third_party_scripts.append({
                    "url": absolute,
                    "integrity": has_integrity,
                })

                # Treat absence as information/possible hardening rather than an automatic vulnerability.
                if not has_integrity:
                    findings.append(make_finding(
                        "sri_missing", "Third-Party Resources",
                        "Third-party script has no SRI attribute",
                        "Info", "High", "Manual Review Required",
                        "An externally hosted script was observed without an integrity attribute.",
                        "For fixed-version CDN resources, consider SRI. Dynamic scripts may not be suitable for SRI.",
                        absolute,
                    ))

    # ---------------- Client-side review ----------------
    client_side = []
    patterns = [
        (r"\beval\s*\(", "eval()", "High"),
        (r"\bdocument\.write\s*\(", "document.write()", "Medium"),
        (r"\.innerHTML\b", "innerHTML", "Low"),
        (r"\blocalStorage\b", "localStorage", "Low"),
    ]

    for pattern, label, base_interest in patterns:
        count = len(re.findall(pattern, html))
        if count:
            client_side.append({"pattern": label, "count": count})
            findings.append(make_finding(
                "client_pattern", "Client-Side Review",
                f"JavaScript review indicator: {label}",
                "Info", "Low", "Manual Review Required",
                f"{label} was found {count} time(s) in the returned page source. This is not proof of a vulnerability.",
                "Review whether untrusted data can reach this API or storage mechanism.",
                f"{count} occurrence(s)",
            ))

    # ---------------- Information exposure / technology ----------------
    technologies = detect_technologies(headers, soup, html)
    disclosures = []

    server = response_headers_original.get("server", "")
    powered = response_headers_original.get("x-powered-by", "")

    for label, value in [("Server", server), ("X-Powered-By", powered)]:
        if value:
            disclosures.append({"type": label, "value": value})
            findings.append(make_finding(
                "server_disclosure", "Information Exposure",
                f"{label} technology information is disclosed",
                "Low", "High", "Confirmed Configuration Finding",
                f"The {label} response header reveals implementation information.",
                "Remove or minimize unnecessary technology/version disclosure where practical.",
                f"{label}: {value}",
            ))

    secret_checks = [
        (
            r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*[\"'][^\"']{12,}[\"']",
            "Possible secret-like value",
        ),
        (
            r"(?i)\b(traceback \(most recent call last\)|uncaught exception|stack trace)\b",
            "Possible debug or stack-trace output",
        ),
    ]

    for pattern, label in secret_checks:
        match = re.search(pattern, html)
        if match:
            evidence = match.group(0)[:160]
            findings.append(make_finding(
                "possible_secret", "Information Exposure",
                label, "Medium", "Low", "Manual Review Required",
                "Public page content matched a sensitive/debug-style pattern.",
                "Review the matched content manually. Remove real secrets or verbose production errors if confirmed.",
                evidence,
            ))

    # Evidence-aware category coverage.
    # "No object observed" is not converted into a perfect security score.
    evidence = {
        "Transport Security": {
            "state": "evaluated",
            "note": "HTTP/HTTPS and TLS behavior can be directly observed for the scanned response."
        },
        "Browser Security": {
            "state": "evaluated",
            "note": "Browser-facing security headers can be directly observed in the response."
        },
        "Cookie Security": {
            "state": "evaluated" if cookies else "not_observed",
            "note": (
                "Observed Set-Cookie attributes were evaluated."
                if cookies else
                "No Set-Cookie header was observed, so cookie security was not scored."
            )
        },
        "Form Security": {
            "state": "evaluated" if forms else "not_observed",
            "note": (
                "Visible HTML forms were passively reviewed."
                if forms else
                "No HTML form was observed in the scanned response, so form security was not scored."
            )
        },
        "Cross-Origin Security": {
            "state": "evaluated" if (
                cors.get("allow_origin") or cors.get("allow_credentials")
            ) else "limited",
            "note": (
                "Observed CORS response headers were evaluated."
                if (cors.get("allow_origin") or cors.get("allow_credentials"))
                else
                "No explicit CORS permission was advertised. Passive inspection alone cannot prove cross-origin security."
            )
        },
        "Third-Party Resources": {
            "state": "evaluated" if (third_party_scripts or mixed_content) else "not_observed",
            "note": (
                "Observed third-party resources were evaluated."
                if (third_party_scripts or mixed_content)
                else
                "No relevant third-party script or mixed-content condition was observed, so this category was not scored."
            )
        },
        "Information Exposure": {
            "state": "limited",
            "note": "WebShield checks selected public disclosure patterns, but absence of a match cannot justify a 100/100 information-security score."
        },
        "Client-Side Review": {
            "state": "limited",
            "note": "Pattern matching can highlight code for review, but passive HTML inspection cannot prove client-side code is secure."
        },
    }

    scoring = calculate_scores(findings, evidence)

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    confidence_counts = {"High": 0, "Medium": 0, "Low": 0}
    status_counts = {}

    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        confidence_counts[f["confidence"]] = confidence_counts.get(f["confidence"], 0) + 1
        status_counts[f["status"]] = status_counts.get(f["status"], 0) + 1

    confirmed_actionable = [
        f for f in findings
        if f["status"] == "Confirmed Configuration Finding" and f["severity"] != "Info"
    ]
    manual_review = [
        f for f in findings
        if f["status"] in {"Manual Review Required", "Potential Concern"}
    ]

    good_news = []
    if uses_https and tls.get("valid"):
        good_news.append("HTTPS is enabled and the TLS certificate validated successfully.")
    if not mixed_content:
        good_news.append("No mixed-content resources were detected on the scanned page.")
    if not cookies:
        good_news.append("No Set-Cookie headers were observed on this response.")
    elif not any(f["category"] == "Cookie Security" and f["severity"] != "Info" for f in findings):
        good_news.append("No significant cookie configuration issue was detected in the observed response.")
    if not any(f["category"] == "Cross-Origin Security" and f["severity"] in {"High", "Medium"} for f in findings):
        good_news.append("No significant CORS configuration issue was detected in the observed response.")

    beginner_summary = {
        "headline": scoring["posture_text"],
        "good_news": good_news[:5],
        "improvements": [
            f["friendly_title"] for f in confirmed_actionable[:5]
        ],
        "manual_review": [
            f["friendly_title"] for f in manual_review[:4]
        ],
        "important_note": (
            "This scan does not prove that a website is completely secure, insecure, hacked, or free from vulnerabilities. "
            "WebShield reviews selected publicly observable security controls and configuration signals."
        ),
    }

    cia = build_cia_summary(findings)
    hackability = build_hackability_summary(findings, scoring["score"])

    result_preview = {
        "final_url": final_url,
        "findings": findings,
    }
    ai_remediation_prompt = build_ai_remediation_prompt(result_preview)

    return {
        "version": "Final 1.0",
        "target_url": normalize_and_validate_url(raw_url),
        "final_url": final_url,
        "status_code": fetched["status_code"],
        "content_type": fetched["content_type"],
        "redirect_count": fetched["redirect_count"],
        "response_truncated": fetched["truncated"],
        "score": scoring["score"],
        "score_name": "WebShield Observed Security Posture",
        "coverage_percent": scoring["coverage_percent"],
        "evaluated_count": scoring["evaluated_count"],
        "total_categories": scoring["total_categories"],
        "raw_score": scoring.get("raw_score"),
        "confirmed_counts": scoring.get("confirmed_counts", {}),
        "assessment_quality": ("High" if scoring["coverage_percent"] >= 80 else
                               "Moderate" if scoring["coverage_percent"] >= 55 else "Low"),
        "posture": scoring["posture"],
        "posture_text": scoring["posture_text"],
        "counts": counts,
        "confidence_counts": confidence_counts,
        "status_counts": status_counts,
        "categories": scoring["categories"],
        "beginner_summary": beginner_summary,
        "hackability": hackability,
        "cia": cia,
        "ai_remediation_prompt": ai_remediation_prompt,
        "tls": tls,
        "headers": security_headers,
        "csp": {
            "present": bool(csp_value),
            "value": csp_value,
            "directives": csp,
        },
        "cors": cors,
        "cookies": cookies,
        "forms": forms,
        "external_domains": sorted(external_domains)[:100],
        "mixed_content": mixed_content[:100],
        "third_party_scripts": third_party_scripts[:100],
        "client_side": client_side,
        "disclosures": disclosures,
        "technologies": technologies,
        "findings": findings,
        "glossary": GLOSSARY,
    }
