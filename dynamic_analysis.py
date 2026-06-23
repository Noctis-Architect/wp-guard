"""Safe dynamic PoC verification for known Critical RCE/SQLi vulnerabilities (Nuclei-style templates)."""

import json
import os
import re
import time
from urllib.parse import urlencode, urljoin

from runtime_paths import database_dir

CACHE_DIR = database_dir()
POC_TEMPLATES_FILE = os.path.join(CACHE_DIR, "poc_templates.json")

RCE_KEYWORDS = (
    "rce",
    "remote code",
    "arbitrary code",
    "arbitrary file",
    "shell",
    "code execution",
    "file upload",
    "file inclusion",
    "unauthenticated upload",
)

SQLI_KEYWORDS = (
    "sql injection",
    "sqli",
    "sql-injection",
    "blind sql",
    "time-based sql",
)

SQL_ERROR_PATTERNS = (
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"sql syntax.*mysql", re.I),
    re.compile(r"warning.*mysqli?", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"sqlite3?\.OperationalError", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"mysql_fetch", re.I),
    re.compile(r"pg_query\(\)", re.I),
)

_templates_cache = None


def _load_templates():
    global _templates_cache
    if _templates_cache is not None:
        return _templates_cache
    if not os.path.exists(POC_TEMPLATES_FILE):
        _templates_cache = []
        return _templates_cache
    try:
        with open(POC_TEMPLATES_FILE, encoding="utf-8") as f:
            data = json.load(f)
        _templates_cache = data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        _templates_cache = []
    return _templates_cache


def classify_vuln_category(vuln):
    """Return 'rce', 'sqli', or None based on vulnerability title/description."""
    text = f"{vuln.get('title', '')} {vuln.get('description', '')}".lower()
    if any(word in text for word in SQLI_KEYWORDS):
        return "sqli"
    if any(word in text for word in RCE_KEYWORDS):
        return "rce"
    return None


def is_eligible_vulnerability(vuln, config):
    """Filter to Critical/High RCE or SQLi issues from passive lookup."""
    severity = (vuln.get("severity") or "").strip()
    min_severity = (config.get("min_severity") or "Critical").strip()
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    if severity_rank.get(severity, 0) < severity_rank.get(min_severity, 4):
        return False

    category = classify_vuln_category(vuln)
    if not category:
        return False
    if category == "rce" and not config.get("test_rce", True):
        return False
    if category == "sqli" and not config.get("test_sqli", True):
        return False
    return True


def _template_matches_vuln(template, vuln):
    slug = (vuln.get("component_slug") or "").strip().lower()
    if template.get("component_slug", "").lower() != slug:
        return False

    kind = (vuln.get("component_type") or "plugin").strip().lower()
    allowed_types = [t.lower() for t in (template.get("component_types") or ["plugin"])]
    if kind not in allowed_types:
        return False

    category = classify_vuln_category(vuln)
    template_cats = [c.lower() for c in (template.get("vuln_categories") or [])]
    if template_cats and category and category not in template_cats:
        return False

    severity = (vuln.get("severity") or "").strip()
    allowed_sev = template.get("severities") or ["Critical", "High"]
    if severity not in allowed_sev:
        return False

    title_keywords = template.get("title_keywords") or []
    title_lower = (vuln.get("title") or "").lower()
    if title_keywords and not all(kw.lower() in title_lower for kw in title_keywords):
        return False

    cve_ids = template.get("cve_ids") or []
    if cve_ids:
        vuln_id = (vuln.get("id") or "").strip().upper()
        if vuln_id not in [c.upper() for c in cve_ids]:
            return False

    return True


def find_templates_for_vuln(vuln):
    return [t for t in _load_templates() if _template_matches_vuln(t, vuln)]


def _detect_sql_error(text):
    if not text:
        return None
    for pattern in SQL_ERROR_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)[:120]
    return None


def _build_url(base_url, path, query=None):
    base = base_url.rstrip("/") + "/"
    clean_path = (path or "").lstrip("/")
    url = urljoin(base, clean_path)
    if query:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{urlencode(query, doseq=True)}"
    return url


def _send_request(session, base_url, req_spec, timeout):
    method = (req_spec.get("method") or "GET").upper()
    paths = req_spec.get("paths") or [""]
    headers = dict(req_spec.get("headers") or {})
    last_error = None

    for path in paths:
        url = _build_url(base_url, path, req_spec.get("query"))
        kwargs = {"timeout": timeout, "headers": headers, "allow_redirects": True}
        try:
            if method == "GET":
                res = session.get(url, **kwargs)
            elif method == "POST":
                if req_spec.get("json") is not None:
                    kwargs["json"] = req_spec["json"]
                elif req_spec.get("body"):
                    kwargs["data"] = req_spec["body"]
                res = session.post(url, **kwargs)
            else:
                res = session.request(method, url, **kwargs)
            return res, path, None
        except Exception as exc:
            last_error = str(exc)
    return None, None, last_error


def _check_matchers(response, matchers, baseline_text=None):
    if not response:
        return False, "no response"

    allowed_status = matchers.get("status")
    if allowed_status and response.status_code not in allowed_status:
        return False, f"status {response.status_code}"

    body = response.text or ""

    for word in matchers.get("body_none") or []:
        if word.lower() in body.lower():
            return False, f"excluded pattern: {word}"

    body_any = matchers.get("body_any") or []
    if body_any and not any(word.lower() in body.lower() for word in body_any):
        return False, "response body did not match expected signatures"

    for pattern in matchers.get("body_regex") or []:
        if not re.search(pattern, body, re.I):
            return False, f"regex mismatch: {pattern}"

    if matchers.get("sql_error"):
        probe_err = _detect_sql_error(body)
        base_err = _detect_sql_error(baseline_text or "")
        if not probe_err or (base_err and probe_err == base_err):
            return False, "no new SQL error signature"
        return True, f"SQL error signature: {probe_err}"

    return True, f"matched (HTTP {response.status_code})"


def _run_fingerprint_probe(session, base_url, template, timeout):
    requests_spec = template.get("requests") or []
    matchers = template.get("matchers") or {}

    for req_spec in requests_spec:
        response, path, error = _send_request(session, base_url, req_spec, timeout)
        if error:
            continue
        matched, detail = _check_matchers(response, matchers)
        if matched:
            return {
                "matched": True,
                "path": path,
                "status_code": response.status_code,
                "detail": detail,
                "probe_type": "fingerprint",
            }
    return {"matched": False, "detail": "no matching response signature"}


def _run_differential_sqli_probe(session, base_url, template, timeout):
    baseline_spec = (template.get("requests") or [{}])[0]
    probe_spec = template.get("probe_request") or baseline_spec

    baseline_res, base_path, base_err = _send_request(session, base_url, baseline_spec, timeout)
    if base_err:
        return {"matched": False, "detail": f"baseline request failed: {base_err}"}

    probe_res, probe_path, probe_err = _send_request(session, base_url, probe_spec, timeout)
    if probe_err:
        return {"matched": False, "detail": f"probe request failed: {probe_err}"}

    baseline_text = baseline_res.text or ""
    probe_text = probe_res.text or ""
    base_sql = _detect_sql_error(baseline_text)
    probe_sql = _detect_sql_error(probe_text)

    if probe_sql and probe_sql != base_sql:
        return {
            "matched": True,
            "path": probe_path or base_path,
            "status_code": probe_res.status_code,
            "detail": f"SQL error on probe only: {probe_sql}",
            "probe_type": "differential_sqli",
        }

    matchers = template.get("matchers") or {}
    if matchers:
        matched, detail = _check_matchers(probe_res, matchers, baseline_text=baseline_text)
        if matched:
            return {
                "matched": True,
                "path": probe_path or base_path,
                "status_code": probe_res.status_code,
                "detail": detail,
                "probe_type": "differential_sqli",
            }

    return {"matched": False, "detail": "no exploitable SQL error signature detected"}


def execute_template_probe(session, base_url, template, timeout=8):
    probe_type = template.get("probe_type") or "fingerprint"
    if probe_type == "differential_sqli":
        return _run_differential_sqli_probe(session, base_url, template, timeout)
    return _run_fingerprint_probe(session, base_url, template, timeout)


def verify_vulnerabilities(
    session,
    base_url,
    known_vulnerabilities,
    config=None,
    log_callback=None,
    timeout=8,
):
    """
    Run safe PoC probes for eligible Critical/High RCE & SQLi findings.

    Returns list of finding dicts with verification status per vulnerability.
    """
    cfg = config or {}
    log = log_callback or (lambda msg, type="info": None)

    if not cfg.get("enabled", True):
        return []

    eligible = [v for v in (known_vulnerabilities or []) if is_eligible_vulnerability(v, cfg)]
    if not eligible:
        log("No Critical/High RCE or SQLi vulnerabilities eligible for dynamic verification.", "info")
        return []

    max_probes = max(1, min(int(cfg.get("max_probes") or 15), 50))
    delay = max(0.0, min(float(cfg.get("delay_seconds") or 0.5), 5.0))
    findings = []
    probes_run = 0
    seen_keys = set()

    log(
        f"Dynamic analysis: verifying up to {min(len(eligible), max_probes)} "
        f"Critical/High RCE·SQLi finding(s) with safe PoC templates...",
        "info",
    )

    for vuln in eligible:
        if probes_run >= max_probes:
            log(f"Dynamic analysis probe limit reached ({max_probes}).", "warning")
            break

        templates = find_templates_for_vuln(vuln)
        if not templates:
            continue

        slug = vuln.get("component_slug", "?")
        title = vuln.get("title", "Unknown")
        category = classify_vuln_category(vuln) or "unknown"

        for template in templates:
            dedupe_key = (slug, template.get("id"), vuln.get("id"))
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)

            if probes_run >= max_probes:
                break

            template_name = template.get("name") or template.get("id")
            log(f"PoC probe [{category.upper()}]: {slug} — {template_name}", "info")
            result = execute_template_probe(session, base_url, template, timeout=timeout)
            probes_run += 1

            finding = {
                "vuln_id": vuln.get("id"),
                "vuln_title": title,
                "component_slug": slug,
                "component_type": vuln.get("component_type", "plugin"),
                "installed_version": vuln.get("installed_version"),
                "severity": vuln.get("severity"),
                "category": category,
                "template_id": template.get("id"),
                "template_name": template_name,
                "safe_note": template.get("safe_note"),
                "verified": bool(result.get("matched")),
                "probe_type": result.get("probe_type", "fingerprint"),
                "path": result.get("path"),
                "status_code": result.get("status_code"),
                "detail": result.get("detail"),
            }
            findings.append(finding)

            if finding["verified"]:
                log(
                    f"CONFIRMED: {slug} — passive CVE matched and live signature detected "
                    f"({result.get('detail', '')})",
                    "warning",
                )
            else:
                log(
                    f"Not confirmed: {slug} — version may be affected but endpoint signature not detected",
                    "info",
                )

            if delay > 0:
                time.sleep(delay)

    confirmed = sum(1 for f in findings if f.get("verified"))
    log(
        f"Dynamic analysis complete — {confirmed} confirmed, "
        f"{len(findings) - confirmed} inconclusive, {probes_run} probe(s) sent.",
        "success" if confirmed == 0 else "warning",
    )
    return findings
