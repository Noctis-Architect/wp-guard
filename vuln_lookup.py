"""Look up WordPress component versions and known vulnerabilities from online sources."""

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from runtime_paths import database_dir
from wordfence_cache import get_cache_status, lookup_component_vulnerabilities


def parse_version(value):
    parts = re.findall(r"\d+", value or "")
    return tuple(int(p) for p in parts) if parts else None

CACHE_DIR = database_dir()
WPSCAN_CACHE_FILE = os.path.join(CACHE_DIR, "wpscan_cache.json")
WPSCAN_CACHE_TTL = 24 * 3600
WPSCAN_BASE = "https://wpscan.com/api/v3"
WP_PLUGIN_API = "https://api.wordpress.org/plugins/info/1.2/"
WP_THEME_API = "https://api.wordpress.org/themes/info/1.2/"
WP_CORE_CHECK = "https://api.wordpress.org/core/version-check/1.7/"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "WP-Guard-Scanner/1.0"})

SEVERITY_FROM_CVSS = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
)


def _read_wpscan_cache():
    if not os.path.exists(WPSCAN_CACHE_FILE):
        return {}
    try:
        with open(WPSCAN_CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_wpscan_cache(data):
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = WPSCAN_CACHE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, WPSCAN_CACHE_FILE)


def _cached_wpscan_get(cache_key, url, api_token):
    cache = _read_wpscan_cache()
    entry = cache.get(cache_key)
    if entry and (time.time() - entry.get("fetched_at", 0)) < WPSCAN_CACHE_TTL:
        return entry.get("data")

    headers = {"Authorization": f"Token token={api_token}"}
    try:
        res = SESSION.get(url, headers=headers, timeout=15)
    except requests.RequestException:
        return None

    if res.status_code == 429:
        return {"_rate_limited": True}
    if res.status_code != 200:
        return None

    try:
        data = res.json()
    except ValueError:
        return None

    cache[cache_key] = {"fetched_at": time.time(), "data": data}
    _write_wpscan_cache(cache)
    return data


def compare_versions(a, b):
    """Return -1 if a < b, 0 if equal, 1 if a > b; None if incomparable."""
    va, vb = parse_version(a), parse_version(b)
    if not va or not vb:
        return None
    length = max(len(va), len(vb))
    va = va + (0,) * (length - len(va))
    vb = vb + (0,) * (length - len(vb))
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def _parse_affected_versions(text):
    """Parse WPScan affected_versions strings like '<= 3.6.3' or '>= 1.0, <= 2.0'."""
    text = (text or "").strip()
    if not text or text in ("*", "-", "all"):
        return [("any", None)]

    rules = []
    for part in re.split(r"\s*,\s*", text):
        part = part.strip()
        if not part:
            continue
        match = re.match(r"(<=|>=|<|>|=)\s*([0-9][0-9.]*)", part)
        if match:
            rules.append((match.group(1), match.group(2)))
        elif re.match(r"^[0-9][0-9.]*$", part):
            rules.append(("=", part))
    return rules or [("any", None)]


def _rule_matches(installed, op, boundary):
    if op == "any":
        return True
    cmp = compare_versions(installed, boundary)
    if cmp is None:
        return False
    if op == "<":
        return cmp < 0
    if op == "<=":
        return cmp <= 0
    if op == ">":
        return cmp > 0
    if op == ">=":
        return cmp >= 0
    if op == "=":
        return cmp == 0
    return False


def is_version_affected(installed_version, vuln):
    """Return True if installed_version is within the vulnerability's affected range."""
    installed = (installed_version or "").strip()
    if not installed or installed.lower() == "unknown":
        return None

    fixed_in = (vuln.get("fixed_in") or "").strip()
    if fixed_in and fixed_in not in ("*", "-"):
        cmp = compare_versions(installed, fixed_in)
        if cmp is not None and cmp >= 0:
            return False

    affected = vuln.get("affected_versions") or ""
    rules = _parse_affected_versions(affected)
    if rules == [("any", None)]:
        return True

    for op, boundary in rules:
        if op == "any":
            return True
        if boundary and _rule_matches(installed, op, boundary):
            return True
    return False


def _severity_from_vuln(vuln):
    cvss = vuln.get("cvss") or {}
    score = cvss.get("score")
    if score is not None:
        try:
            score = float(score)
            for threshold, label in SEVERITY_FROM_CVSS:
                if score >= threshold:
                    return label
        except (TypeError, ValueError):
            pass

    title = (vuln.get("title") or "").lower()
    if any(word in title for word in ("rce", "remote code", "arbitrary code", "shell")):
        return "Critical"
    if any(word in title for word in ("sql injection", "authentication bypass", "privilege")):
        return "High"
    return "Medium"


def _normalize_vuln(vuln, component_type, slug, installed_version):
    refs = vuln.get("references") or {}
    links = []
    if isinstance(refs, dict):
        for key in ("url", "cve", "wpvulndb", "exploitdb"):
            value = refs.get(key)
            if isinstance(value, list):
                links.extend(str(v) for v in value if v)
            elif value:
                links.append(str(value))

    return {
        "id": vuln.get("id"),
        "title": (vuln.get("title") or "Unknown vulnerability").strip(),
        "description": (vuln.get("description") or "").strip(),
        "severity": _severity_from_vuln(vuln),
        "fixed_in": (vuln.get("fixed_in") or "").strip() or None,
        "affected_versions": (vuln.get("affected_versions") or "").strip() or None,
        "published": vuln.get("published_date") or vuln.get("created_at"),
        "verified": bool(vuln.get("verified")),
        "references": links[:8],
        "component_type": component_type,
        "component_slug": slug,
        "installed_version": installed_version,
        "source": "wpscan",
    }


def fetch_latest_plugin_version(slug):
    try:
        res = SESSION.get(
            WP_PLUGIN_API,
            params={"action": "plugin_information", "request[slug]": slug},
            timeout=12,
        )
        if res.status_code == 200:
            data = res.json()
            return (data.get("version") or "").strip() or None
    except requests.RequestException:
        pass
    return None


def fetch_latest_theme_version(slug):
    try:
        res = SESSION.get(
            WP_THEME_API,
            params={"action": "theme_information", "request[slug]": slug},
            timeout=12,
        )
        if res.status_code == 200:
            data = res.json()
            return (data.get("version") or "").strip() or None
    except requests.RequestException:
        pass
    return None


def fetch_wordpress_core_status(installed_version):
    if not installed_version or installed_version.lower() == "unknown":
        return None
    try:
        res = SESSION.get(
            WP_CORE_CHECK,
            params={"version": installed_version},
            timeout=12,
        )
        if res.status_code != 200:
            return None
        data = res.json()
        offers = data.get("offers") or []
        latest = None
        for offer in offers:
            if offer.get("response") == "upgrade":
                latest = offer.get("version")
                break
        if not latest and offers:
            latest = offers[0].get("version")
        outdated = bool(latest and compare_versions(installed_version, latest) == -1)
        return {
            "installed_version": installed_version,
            "latest_version": latest,
            "outdated": outdated,
            "source": "wordpress.org",
        }
    except (requests.RequestException, ValueError):
        return None


def fetch_wpscan_component(kind, slug, api_token):
    if not api_token:
        return None
    url = f"{WPSCAN_BASE}/{kind}/{slug}"
    return _cached_wpscan_get(f"{kind}:{slug}", url, api_token)


def _wpscan_vulns_for_version(wpscan_data, component_type, slug, installed_version):
    if not wpscan_data or wpscan_data.get("_rate_limited"):
        return [], wpscan_data

    raw_vulns = wpscan_data.get("vulnerabilities") or []
    matched = []
    for vuln in raw_vulns:
        affected = is_version_affected(installed_version, vuln)
        if affected is True:
            matched.append(_normalize_vuln(vuln, component_type, slug, installed_version))
    return matched, None


def _merge_vuln_lists(*lists):
    seen = set()
    merged = []
    for vulns in lists:
        for vuln in vulns or []:
            key = (vuln.get("source"), vuln.get("id"), vuln.get("title"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(vuln)
    return merged


def enrich_component(component, kind, api_token=None, use_wordfence=True):
    """Add latest_version, outdated flag, and known vulnerabilities to a plugin/theme dict."""
    slug = component.get("slug") or ""
    version = (component.get("version") or "Unknown").strip()
    is_plugin = kind == "plugin"

    latest = fetch_latest_plugin_version(slug) if is_plugin else fetch_latest_theme_version(slug)
    component["latest_version"] = latest

    outdated = False
    if latest and version.lower() != "unknown":
        cmp = compare_versions(version, latest)
        outdated = cmp == -1 if cmp is not None else False
    component["outdated"] = outdated

    vulns = []
    if use_wordfence and get_cache_status().get("ready"):
        wf_kind = "plugin" if is_plugin else "theme"
        wf_vulns = lookup_component_vulnerabilities(wf_kind, slug, version)
        vulns.extend(wf_vulns)

    wpscan_data = fetch_wpscan_component("plugins" if is_plugin else "themes", slug, api_token)
    if wpscan_data:
        if wpscan_data.get("_rate_limited"):
            component["vuln_lookup_error"] = "WPScan API rate limit reached"
        else:
            matched, _ = _wpscan_vulns_for_version(wpscan_data, kind, slug, version)
            vulns = _merge_vuln_lists(vulns, matched)
            wpscan_latest = (wpscan_data.get("latest_version") or "").strip()
            if wpscan_latest and not latest:
                component["latest_version"] = wpscan_latest

    component["known_vulnerabilities"] = vulns
    component["vulnerable"] = bool(vulns)
    return component


def enrich_scan_components(plugins, themes, wp_version, api_token=None, log_callback=None, max_workers=8):
    """Check all detected components against wordpress.org and WPScan."""
    log = log_callback or (lambda msg, type="info": None)
    api_token = (api_token or "").strip()
    wf_status = get_cache_status()

    if wf_status.get("ready"):
        log(
            f"Checking components against local Wordfence database ({wf_status.get('record_count', 0):,} records)...",
            "info",
        )
    elif api_token:
        log("Querying WPScan vulnerability database for detected components...", "info")
    else:
        log(
            "Checking component versions on wordpress.org (add Wordfence or WPScan API key in Settings for CVE lookup)...",
            "info",
        )

    core_status = fetch_wordpress_core_status(wp_version)
    all_vulns = []

    def process(item, kind):
        enriched = enrich_component(dict(item), kind, api_token=api_token)
        return enriched, kind

    items = [(p, "plugin") for p in plugins] + [(t, "theme") for t in themes]
    results_by_key = {}
    rate_limited = False

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(process, item, kind): (item, kind) for item, kind in items}
        for fut in as_completed(futures):
            original, kind = futures[fut]
            try:
                enriched, _ = fut.result()
            except Exception:
                enriched = dict(original)
                enriched.setdefault("known_vulnerabilities", [])
                enriched.setdefault("vulnerable", False)

            if enriched.get("vuln_lookup_error"):
                rate_limited = True

            slug = enriched.get("slug", "?")
            version = enriched.get("version", "?")
            vuln_count = len(enriched.get("known_vulnerabilities") or [])

            if vuln_count:
                log(
                    f"VULNERABLE: {slug} v{version} — {vuln_count} known issue(s) for this version",
                    "warning",
                )
                for v in enriched["known_vulnerabilities"][:2]:
                    log(f"  ↳ [{v['severity']}] {v['title']}", "warning")
            elif enriched.get("outdated"):
                latest = enriched.get("latest_version", "?")
                log(f"Outdated {kind}: {slug} v{version} (latest: v{latest})", "warning")
            elif enriched.get("latest_version"):
                log(f"{slug} v{version} is up to date (latest: v{enriched['latest_version']})", "success")

            for v in enriched.get("known_vulnerabilities") or []:
                all_vulns.append(v)

            results_by_key[(kind, slug)] = enriched

    enriched_plugins = [results_by_key[("plugin", p.get("slug"))] for p in plugins if ("plugin", p.get("slug")) in results_by_key]
    enriched_themes = [results_by_key[("theme", t.get("slug"))] for t in themes if ("theme", t.get("slug")) in results_by_key]

    if core_status and core_status.get("outdated"):
        log(
            f"WordPress core v{wp_version} is outdated (latest: v{core_status.get('latest_version')})",
            "warning",
        )

    return {
        "plugins": enriched_plugins,
        "themes": enriched_themes,
        "core_status": core_status,
        "known_vulnerabilities": all_vulns,
        "wpscan_enabled": bool(api_token),
        "wordfence_enabled": bool(wf_status.get("ready")),
        "wordfence_updated_at": wf_status.get("updated_at"),
        "wpscan_rate_limited": rate_limited,
    }
