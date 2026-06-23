"""Download and cache the Wordfence Intelligence vulnerability feed for offline lookup."""

import json
import os
import threading
import time
from datetime import datetime, timezone

import requests

from runtime_paths import database_dir

CACHE_DIR = database_dir()
FEED_FILE = os.path.join(CACHE_DIR, "wordfence_vulns.json")
INDEX_FILE = os.path.join(CACHE_DIR, "wordfence_index.json")
META_FILE = os.path.join(CACHE_DIR, "wordfence_meta.json")

WORDFENCE_FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "WP-Guard-Scanner/1.0"})

_lock = threading.Lock()
_index_cache = None
_meta_cache = None

SEVERITY_FROM_CVSS = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
)


class WordfenceCacheError(Exception):
    pass


def _component_key(software_type, slug):
    return f"{(software_type or '').strip().lower()}:{(slug or '').strip().lower()}"


def _read_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _write_json(path, data):
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


def _severity_from_cvss(cvss, title=""):
    if isinstance(cvss, dict):
        rating = (cvss.get("rating") or "").strip()
        if rating:
            return rating.title()
        score = cvss.get("score")
        if score is not None:
            try:
                score = float(score)
                for threshold, label in SEVERITY_FROM_CVSS:
                    if score >= threshold:
                        return label
            except (TypeError, ValueError):
                pass

    title_lower = (title or "").lower()
    if any(word in title_lower for word in ("rce", "remote code", "arbitrary code", "shell")):
        return "Critical"
    if any(word in title_lower for word in ("sql injection", "authentication bypass", "privilege")):
        return "High"
    return "Medium"


def _parse_version(value):
    import re

    parts = re.findall(r"\d+", value or "")
    return tuple(int(p) for p in parts) if parts else None


def compare_versions(a, b):
    va, vb = _parse_version(a), _parse_version(b)
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


def _version_matches_rule(installed, rule):
    from_version = rule.get("from_version") or "*"
    to_version = rule.get("to_version") or "*"
    from_inclusive = bool(rule.get("from_inclusive"))
    to_inclusive = bool(rule.get("to_inclusive"))

    if from_version == "*" and to_version == "*":
        return True

    if from_version != "*":
        cmp = compare_versions(installed, from_version)
        if cmp is None:
            return False
        if from_inclusive:
            if cmp < 0:
                return False
        elif cmp <= 0:
            return False

    if to_version != "*":
        cmp = compare_versions(installed, to_version)
        if cmp is None:
            return False
        if to_inclusive:
            if cmp > 0:
                return False
        elif cmp >= 0:
            return False

    return True


def _iter_affected_version_rules(affected_versions):
    if not affected_versions:
        return
    if isinstance(affected_versions, dict):
        for rule in affected_versions.values():
            if isinstance(rule, dict):
                yield rule
    elif isinstance(affected_versions, list):
        for rule in affected_versions:
            if isinstance(rule, dict):
                yield rule


def is_version_affected(installed_version, software_entry):
    installed = (installed_version or "").strip()
    if not installed or installed.lower() == "unknown":
        return None

    if software_entry.get("patched"):
        for fixed in software_entry.get("patched_versions") or []:
            cmp = compare_versions(installed, fixed)
            if cmp is not None and cmp >= 0:
                return False

    rules = list(_iter_affected_version_rules(software_entry.get("affected_versions")))
    if not rules:
        return False

    for rule in rules:
        if _version_matches_rule(installed, rule):
            return True
    return False


def _compact_vuln_record(vuln_id, vuln, software_entry):
    refs = vuln.get("references") or []
    links = [str(r) for r in refs if r][:8]
    cvss = vuln.get("cvss") if isinstance(vuln.get("cvss"), dict) else {}
    title = (vuln.get("title") or "Unknown vulnerability").strip()
    patched_versions = software_entry.get("patched_versions") or []
    fixed_in = patched_versions[0] if patched_versions else None

    return {
        "id": vuln.get("cve") or vuln_id,
        "wordfence_id": vuln_id,
        "title": title,
        "description": (software_entry.get("remediation") or "").strip(),
        "severity": _severity_from_cvss(cvss, title),
        "fixed_in": fixed_in,
        "affected_versions": software_entry.get("affected_versions"),
        "published": vuln.get("published"),
        "verified": True,
        "references": links,
        "source": "wordfence",
        "software": {
            "type": software_entry.get("type"),
            "slug": software_entry.get("slug"),
            "name": software_entry.get("name"),
            "patched": software_entry.get("patched"),
            "patched_versions": patched_versions,
        },
    }


def build_index(feed_data):
    by_component = {}
    record_count = 0

    if not isinstance(feed_data, dict):
        raise WordfenceCacheError("Unexpected Wordfence feed format.")

    for vuln_id, vuln in feed_data.items():
        if not isinstance(vuln, dict):
            continue
        record_count += 1
        for software in vuln.get("software") or []:
            if not isinstance(software, dict):
                continue
            slug = (software.get("slug") or "").strip()
            software_type = (software.get("type") or "").strip().lower()
            if not slug or software_type not in ("plugin", "theme", "core"):
                continue
            key = _component_key(software_type, slug)
            by_component.setdefault(key, []).append(_compact_vuln_record(vuln_id, vuln, software))

    return {
        "updated_at": time.time(),
        "record_count": record_count,
        "component_count": len(by_component),
        "by_component": by_component,
    }


def download_feed(api_key, progress_callback=None):
    api_key = (api_key or "").strip()
    if not api_key:
        raise WordfenceCacheError("Wordfence API key is required.")

    log = progress_callback or (lambda msg, type="info": None)
    headers = {"Authorization": f"Bearer {api_key}"}
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp_path = FEED_FILE + ".download"

    log("Downloading Wordfence vulnerability database (this may take several minutes)...", "info")

    try:
        with SESSION.get(WORDFENCE_FEED_URL, headers=headers, stream=True, timeout=600) as res:
            if res.status_code == 401:
                raise WordfenceCacheError("Invalid Wordfence API key.")
            if res.status_code == 429:
                raise WordfenceCacheError("Wordfence API rate limit reached. Try again later.")
            if res.status_code != 200:
                detail = res.text[:300] if res.text else res.status_code
                raise WordfenceCacheError(f"Wordfence download failed: {detail}")

            total = int(res.headers.get("content-length") or 0)
            downloaded = 0
            last_report = 0.0

            with open(tmp_path, "wb") as out:
                for chunk in res.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    out.write(chunk)
                    downloaded += len(chunk)
                    if total and time.monotonic() - last_report >= 2.0:
                        pct = min(100, int(downloaded * 100 / total))
                        log(f"Wordfence download progress: {pct}% ({downloaded // (1024 * 1024)} MB)", "info")
                        last_report = time.monotonic()
    except requests.RequestException as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise WordfenceCacheError(f"Could not download Wordfence feed: {e}") from e

    os.replace(tmp_path, FEED_FILE)
    log("Wordfence feed downloaded. Building lookup index...", "info")
    return FEED_FILE


def refresh_wordfence_cache(api_key, force=False, progress_callback=None):
    """Download feed and rebuild local index."""
    global _index_cache, _meta_cache

    with _lock:
        meta = _read_json(META_FILE) or {}
        if meta.get("updated_at") and not force and os.path.exists(INDEX_FILE):
            return get_cache_status()

        download_feed(api_key, progress_callback=progress_callback)

        feed_data = _read_json(FEED_FILE)
        if not feed_data:
            raise WordfenceCacheError("Downloaded Wordfence feed could not be parsed.")

        if isinstance(feed_data, dict) and feed_data.get("errors"):
            errors = feed_data["errors"]
            message = errors[0].get("detail") if errors else "Unknown Wordfence API error"
            raise WordfenceCacheError(message or "Wordfence API error.")

        index = build_index(feed_data)
        _write_json(INDEX_FILE, index)

        meta = {
            "updated_at": index["updated_at"],
            "record_count": index["record_count"],
            "component_count": index["component_count"],
            "feed_size_bytes": os.path.getsize(FEED_FILE),
        }
        _write_json(META_FILE, meta)

        _index_cache = index
        _meta_cache = meta
        return get_cache_status()


def get_cache_status():
    meta = _read_json(META_FILE) or {}
    updated_at = meta.get("updated_at")
    updated_label = None
    if updated_at:
        updated_label = datetime.fromtimestamp(updated_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return {
        "ready": bool(os.path.exists(INDEX_FILE)),
        "updated_at": updated_at,
        "updated_label": updated_label,
        "record_count": meta.get("record_count", 0),
        "component_count": meta.get("component_count", 0),
        "feed_size_mb": round((meta.get("feed_size_bytes") or 0) / (1024 * 1024), 1),
    }


def _load_index():
    global _index_cache
    if _index_cache is not None:
        return _index_cache
    _index_cache = _read_json(INDEX_FILE) or {"by_component": {}}
    return _index_cache


def lookup_component_vulnerabilities(component_type, slug, installed_version):
    """Return Wordfence vulnerabilities affecting the installed version."""
    key = _component_key(component_type, slug)
    index = _load_index()
    records = (index.get("by_component") or {}).get(key) or []

    matched = []
    for record in records:
        software_entry = {
            "affected_versions": record.get("affected_versions"),
            "patched": (record.get("software") or {}).get("patched"),
            "patched_versions": (record.get("software") or {}).get("patched_versions") or [],
        }
        affected = is_version_affected(installed_version, software_entry)
        if affected is True:
            item = dict(record)
            item["component_type"] = "plugin" if component_type == "plugin" else ("theme" if component_type == "theme" else "core")
            item["component_slug"] = slug
            item["installed_version"] = installed_version
            matched.append(item)
    return matched


def ensure_wordfence_ready(api_key_getter, background=True, progress_callback=None):
    """Download Wordfence data once if API key is set and cache is missing."""
    api_key = (api_key_getter() or "").strip()
    if not api_key:
        return get_cache_status()

    status = get_cache_status()
    if status.get("ready"):
        return status

    if background:
        thread = threading.Thread(
            target=_background_refresh,
            args=(api_key, progress_callback),
            daemon=True,
            name="wordfence-initial-sync",
        )
        thread.start()
        return status

    return refresh_wordfence_cache(api_key, force=True, progress_callback=progress_callback)


def _background_refresh(api_key, progress_callback):
    try:
        refresh_wordfence_cache(api_key, force=True, progress_callback=progress_callback)
    except WordfenceCacheError:
        pass
