import copy
import json
import os

from models import AppSettings, db

DEFAULT_SYSTEM_PROMPT = """You are an elite WordPress security auditor with deep expertise in penetration testing, hardening, and incident response.

You receive raw JSON output from WP Guard, an automated WordPress vulnerability scanner. Your job is to turn technical findings into actionable intelligence for the site owner or administrator.

## Your responsibilities

1. **Risk assessment** — Evaluate each finding for real-world exploitability, not just scanner labels. Distinguish confirmed issues from probable false positives.
2. **Impact analysis** — Explain what an attacker could achieve (data breach, defacement, privilege escalation, SEO spam, etc.).
3. **Remediation** — For every confirmed or likely issue, provide clear, step-by-step fix instructions:
   - WordPress admin panel steps where applicable
   - wp-config.php / .htaccess / nginx configuration snippets
   - Plugin or theme update paths
   - CLI commands (WP-CLI) when helpful
4. **Version & CVE analysis** — For every WordPress core, plugin, and theme version in the scan:
   - Review `known_vulnerabilities` and `component_vulnerabilities` from the WPScan / wordpress.org lookup.
   - State clearly whether the **installed version** is affected by any **Critical or High** CVE.
   - If lookup data is missing but the version is outdated, warn based on your knowledge of common WordPress security issues.
   - Include a dedicated `## Version & CVE Findings` section listing each component, its version, and exploit risk.
5. **Prioritization** — Group fixes into: **Immediate** (do now), **Short-term** (this week), **Long-term** (hardening).
6. **Overall posture** — Give a security grade (A–F) with a one-paragraph executive summary.

## Output format

Respond in well-structured Markdown:
- `## Executive Summary`
- `## Version & CVE Findings` (core, plugins, themes — version, known CVEs, dangerous or not)
- `## Critical & High Priority Findings` (each with Risk / Impact / Fix)
- `## Medium & Low Priority Findings`
- `## False Positives / Needs Manual Verification`
- `## Recommended Hardening Checklist`
- `## Action Plan`

Be direct, practical, and thorough. If the scanned site or its content is Persian/Farsi, write the entire report in Persian (فارسی) using proper UTF-8 characters."""

DEFAULT_SCAN_SETTINGS = {
    "vuln_lookup": {
        "enabled": True,
        "wpscan_api_token": "",
        "wordfence_api_key": "",
    },
    "injection": {
        "enabled": True,
        "max_forms": 8,
        "test_sql": True,
        "test_xss": True,
    },
    "dynamic_analysis": {
        "enabled": True,
        "max_probes": 15,
        "delay_seconds": 0.5,
        "test_rce": True,
        "test_sqli": True,
        "min_severity": "Critical",
    },
}

DEFAULT_SETTINGS = {
    "proxy": {
        "enabled": False,
        "url": "",
    },
    "ai": {
        "enabled": False,
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key": "",
        "model": "gpt-4o-mini",
        "system_prompt": DEFAULT_SYSTEM_PROMPT,
        "auto_analyze": True,
    },
    "scan": DEFAULT_SCAN_SETTINGS,
}

PROVIDER_PRESETS = {
    "openai": {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
    "ollama": {"base_url": "http://localhost:11434/v1", "model": "llama3.2"},
    "custom": {"base_url": "", "model": ""},
}


def _deep_merge(base, override):
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_stored_settings():
    """Load persisted settings from SQLite (no .env overlay)."""
    row = AppSettings.query.first()
    if not row:
        return copy.deepcopy(DEFAULT_SETTINGS)
    try:
        stored = json.loads(row.data_json)
    except (json.JSONDecodeError, TypeError):
        stored = {}
    return _deep_merge(DEFAULT_SETTINGS, stored)


def _apply_env_defaults(settings):
    merged = copy.deepcopy(settings)
    vuln = merged.setdefault("scan", {}).setdefault("vuln_lookup", {})
    env_wf = (os.environ.get("WORDFENCE_API_KEY") or "").strip()
    if env_wf and not (vuln.get("wordfence_api_key") or "").strip():
        vuln["wordfence_api_key"] = env_wf
    return merged


def get_settings():
    return _apply_env_defaults(_load_stored_settings())


def save_settings(data):
    merged = _deep_merge(DEFAULT_SETTINGS, data or {})
    row = AppSettings.query.first()
    if not row:
        row = AppSettings(data_json=json.dumps(merged))
        db.session.add(row)
    else:
        row.data_json = json.dumps(merged)
    db.session.commit()
    return merged


def settings_for_client():
    """Return settings safe to expose to the frontend (mask API key)."""
    stored = _load_stored_settings()
    s = _apply_env_defaults(stored)
    out = copy.deepcopy(s)
    key = out["ai"].get("api_key", "")
    out["ai"]["api_key_set"] = bool(key)
    out["ai"]["api_key"] = ""
    vuln = out.get("scan", {}).get("vuln_lookup", {})
    stored_vuln = stored.get("scan", {}).get("vuln_lookup", {})
    wpscan = (vuln.get("wpscan_api_token") or "").strip()
    out.setdefault("scan", {}).setdefault("vuln_lookup", {})["wpscan_api_token_set"] = bool(wpscan)
    out["scan"]["vuln_lookup"]["wpscan_api_token"] = ""
    db_wf = (stored_vuln.get("wordfence_api_key") or "").strip()
    env_wf = (os.environ.get("WORDFENCE_API_KEY") or "").strip()
    out["scan"]["vuln_lookup"]["wordfence_api_key_set"] = bool(db_wf or env_wf)
    out["scan"]["vuln_lookup"]["wordfence_api_key_from_env"] = bool(env_wf and not db_wf)
    out["scan"]["vuln_lookup"]["wordfence_api_key"] = ""
    return out


def get_wordfence_api_key():
    stored = _load_stored_settings()
    key = (stored.get("scan", {}).get("vuln_lookup", {}).get("wordfence_api_key") or "").strip()
    if key:
        return key
    return (os.environ.get("WORDFENCE_API_KEY") or "").strip()


def get_proxy_dict():
    """Build requests-compatible proxies dict, or None if disabled."""
    proxy_cfg = get_settings().get("proxy", {})
    if not proxy_cfg.get("enabled"):
        return None
    url = (proxy_cfg.get("url") or "").strip()
    if not url:
        return None
    return {"http": url, "https": url}
