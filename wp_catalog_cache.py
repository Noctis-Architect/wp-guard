"""Fetch and cache popular WordPress plugins/themes from wordpress.org."""

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from runtime_paths import database_dir

CACHE_DIR = database_dir()
CACHE_FILE = os.path.join(CACHE_DIR, "wp_catalog.json")
CACHE_TTL_SECONDS = 7 * 24 * 3600  # refresh weekly
TARGET_COUNT = 500
PER_PAGE = 100
FETCH_WORKERS = 5

PLUGINS_API = "https://api.wordpress.org/plugins/info/1.2/"
THEMES_API = "https://api.wordpress.org/themes/info/1.2/"

_lock = threading.Lock()

FALLBACK_PLUGINS = [
    "akismet", "elementor", "woocommerce", "contact-form-7", "wordpress-seo",
    "jetpack", "wpforms-lite", "wordfence", "all-in-one-seo-pack", "duplicator",
    "wp-file-manager", "revslider", "classic-editor", "really-simple-ssl",
]

FALLBACK_THEMES = [
    "twentytwentyfour", "twentytwentythree", "twentytwentytwo", "twentytwentyone",
    "twentytwenty", "astra", "divi", "oceanwp", "generatepress", "hello-elementor",
    "kadence", "neve", "storefront",
]


def _fetch_page(session, api_url, action, page):
    params = {
        "action": action,
        "browse": "popular",
        "per_page": PER_PAGE,
        "page": page,
    }
    res = session.get(api_url, params=params, timeout=30)
    res.raise_for_status()
    data = res.json()
    key = "plugins" if action == "query_plugins" else "themes"
    items = data.get(key, [])
    return [item["slug"] for item in items if item.get("slug")]


def _fetch_catalog(api_url, action, target=TARGET_COUNT):
    """Paginate wordpress.org API until we have `target` unique slugs (popularity order)."""
    session = requests.Session()
    session.headers.update({"User-Agent": "WP-Guard-Scanner/1.0"})
    pages_needed = (target + PER_PAGE - 1) // PER_PAGE
    page_results = {}

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        futures = {
            pool.submit(_fetch_page, session, api_url, action, page): page
            for page in range(1, pages_needed + 1)
        }
        for fut in as_completed(futures):
            page = futures[fut]
            try:
                page_results[page] = fut.result()
            except Exception:
                page_results[page] = []

    slugs = []
    seen = set()
    for page in sorted(page_results):
        for slug in page_results[page]:
            if slug not in seen:
                seen.add(slug)
                slugs.append(slug)
                if len(slugs) >= target:
                    return slugs
    return slugs


def _read_cache():
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(data):
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = CACHE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CACHE_FILE)


def _is_stale(cache):
    if not cache:
        return True
    updated = cache.get("updated_at", 0)
    return (time.time() - updated) > CACHE_TTL_SECONDS


def refresh_catalog(force=False):
    """Download top plugins/themes from wordpress.org and persist to disk."""
    with _lock:
        cache = _read_cache()
        if cache and not force and not _is_stale(cache):
            return cache

        plugins = _fetch_catalog(PLUGINS_API, "query_plugins", TARGET_COUNT)
        themes = _fetch_catalog(THEMES_API, "query_themes", TARGET_COUNT)

        if len(plugins) < 50:
            plugins = FALLBACK_PLUGINS
        if len(themes) < 20:
            themes = FALLBACK_THEMES

        data = {
            "updated_at": time.time(),
            "plugins": plugins,
            "themes": themes,
            "plugin_count": len(plugins),
            "theme_count": len(themes),
        }
        _write_cache(data)
        return data


def get_popular_plugins():
    cache = _read_cache()
    if cache and not _is_stale(cache) and cache.get("plugins"):
        return cache["plugins"]
    return refresh_catalog().get("plugins", FALLBACK_PLUGINS)


def get_popular_themes():
    cache = _read_cache()
    if cache and not _is_stale(cache) and cache.get("themes"):
        return cache["themes"]
    return refresh_catalog().get("themes", FALLBACK_THEMES)


def ensure_catalog_ready(background=True):
    """Warm cache on startup; optionally fetch in a background thread."""
    cache = _read_cache()
    if cache and not _is_stale(cache):
        return cache

    if background:
        thread = threading.Thread(target=refresh_catalog, daemon=True, name="wp-catalog-refresh")
        thread.start()
        if cache:
            return cache
        return {"plugins": FALLBACK_PLUGINS, "themes": FALLBACK_THEMES, "updated_at": 0}

    return refresh_catalog()
