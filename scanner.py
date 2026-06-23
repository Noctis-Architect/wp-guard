import copy
import json
import re
import threading
import time
from collections import Counter
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from dynamic_analysis import verify_vulnerabilities as run_dynamic_verification
from settings_manager import DEFAULT_SCAN_SETTINGS
from vuln_lookup import enrich_scan_components
from wp_catalog_cache import get_popular_plugins, get_popular_themes

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

LISTING_ROOT_DIRS = [
    "wp-content/",
    "wp-content/uploads/",
    "wp-content/plugins/",
    "wp-includes/",
    "wp-content/themes/",
    "wp-content/backup/",
    "wp-content/backups/",
    "uploads/",
]

SENSITIVE_DIR_KEYWORDS = (
    "backup",
    "backups",
    "bak",
    "old",
    "temp",
    "tmp",
    "private",
    "secret",
    "admin",
    "user",
    "users",
    "data",
    "dump",
    "dumps",
    "sql",
    "db",
    "database",
    "config",
    "conf",
    "log",
    "logs",
    "cache",
    "export",
    "imports",
    "archive",
    "archives",
    "storage",
    "secure",
    "hidden",
    "wordpress",
)

SENSITIVE_FILE_RULES = [
    (re.compile(r"wp-config", re.I), "Critical", "WordPress configuration backup or leak"),
    (re.compile(r"\.(sql|sql\.gz|sql\.zip|sqlite|db)$", re.I), "Critical", "Database dump exposed"),
    (re.compile(r"\.(bak|backup|old|orig|save|swp|~)$", re.I), "Critical", "Backup file exposed"),
    (re.compile(r"\.(zip|tar|tgz|tar\.gz|rar|7z)$", re.I), "High", "Archive possibly containing site backup"),
    (
        re.compile(r"(\.env|credentials|password|passwd|secret|token|api[_-]?key)", re.I),
        "Critical",
        "Secrets or credentials file",
    ),
    (
        re.compile(r"(user|users|username|members)\.(txt|csv|json|xml|sql)", re.I),
        "High",
        "User data file exposed",
    ),
    (re.compile(r"id_rsa|\.pem|\.ppk|private[_-]?key", re.I), "Critical", "Private key exposed"),
    (re.compile(r"debug\.log|error[_-]?log|php\.log", re.I), "Medium", "Log file may contain sensitive data"),
    (re.compile(r"\.htaccess", re.I), "Medium", "Server configuration file exposed"),
    (re.compile(r"\.git", re.I), "High", "Git metadata exposed"),
    (
        re.compile(r"(^|[-_.])(backup|backups|dump|database|users?|passwd|password|credentials)([-_.]|\.|$)", re.I),
        "High",
        "Sensitive filename exposed in directory listing",
    ),
]

SUSPICIOUS_PHP_PATTERN = re.compile(
    r"(?:shell|backdoor|c99|r57|wso|phpinfo|info|config|backup|dump|upload|admin|test)\.php$",
    re.I,
)

IMAGE_EXTENSIONS = frozenset(
    {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico", ".avif", ".tiff", ".tif", ".heic", ".heif"}
)

UPLOAD_PATH_MARKERS = ("wp-content/uploads/", "uploads/")
UPLOAD_LISTING_MAX_DEPTH = 4
DEFAULT_LISTING_MAX_DEPTH = 2

CDN_HEADER_RULES = (
    ("Cloudflare", ("cf-ray", "cf-cache-status", "cf-request-id")),
    ("Amazon CloudFront", ("x-amz-cf-id", "x-amz-cf-pop", "x-amz-cf-ray")),
    ("Fastly", ("x-fastly-request-id", "x-served-by", "fastly-debug-path")),
    ("Akamai", ("x-akamai-transformed", "akamai-origin-hop")),
    ("Sucuri", ("x-sucuri-id", "x-sucuri-cache")),
    ("StackPath", ("x-cdn", "x-stackpath")),
    ("KeyCDN", ("x-edge-location",)),
    ("BunnyCDN", ("cdn-pullzone", "cdn-requestid")),
    ("Imperva", ("x-cdn", "x-iinfo")),
)

CDN_SERVER_PATTERNS = (
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"cloudfront", re.I), "Amazon CloudFront"),
    (re.compile(r"akamaighost", re.I), "Akamai"),
    (re.compile(r"sucuri", re.I), "Sucuri"),
)

COMPONENT_SLUG_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*$")
MIN_COMPONENT_SLUG_LEN = 2

VERSION_TAG_VALUE = r"([\d][\d.]*(?:[-_][\w.]+)?|trunk|dev)"
PLUGIN_README_VERSION = re.compile(rf"(?im)^\s*Stable tag:\s*{VERSION_TAG_VALUE}\s*$")
PLUGIN_README_VERSION_FALLBACK = re.compile(rf"(?i)Stable tag:\s*{VERSION_TAG_VALUE}")
PLUGIN_HEADER_VERSION = re.compile(rf"(?im)^\s*Version:\s*{VERSION_TAG_VALUE}\s*$")
PLUGIN_HEADER_VERSION_FALLBACK = re.compile(rf"(?i)\bVersion:\s*{VERSION_TAG_VALUE}")
THEME_STYLE_VERSION = re.compile(rf"(?im)^\s*Version:\s*{VERSION_TAG_VALUE}\s*$")
THEME_STYLE_VERSION_FALLBACK = re.compile(rf"(?i)\bVersion:\s*{VERSION_TAG_VALUE}")
ASSET_VERSION_PARAM = re.compile(r"[?&]ver=([^&\"'\s<>]+)")
WP_INCLUDES_VERSION = re.compile(
    r"wp-includes/[^\"'\s>]+[?&]ver=([\d]+\.[\d]+(?:\.[\d]+)?)",
    re.I,
)

SECURITY_PLUGIN_SLUGS = frozenset(
    {
        "wordfence",
        "wordfence-login-security",
        "sucuri-scanner",
        "better-wp-security",
        "ithemes-security",
        "ithemes-security-pro",
        "all-in-one-wp-security-and-firewall",
        "aiowps",
        "bulletproof-security",
        "shield-security",
        "wp-security-audit-log",
        "wp-hardening",
        "cerber-security",
        "wp-cerber",
        "ninjafirewall",
        "ninja-firewall",
        "patchstack",
        "malcare-security",
        "malcare",
        "defender-security",
        "wp-defender",
        "secupress",
        "sg-security",
        "solid-security",
        "loginizer",
        "limit-login-attempts-reloaded",
        "limit-login-attempts",
    }
)

REST_API_MAX_SCORE = 25

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

SQL_PAYLOADS = (
    "'",
    "' OR '1'='1",
    "1' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1 AND 1=1",
)

XSS_PROBE_MARKER = "wpguardxssprobe7k"
XSS_PAYLOADS = (
    f'"><svg data-probe="{XSS_PROBE_MARKER}">',
    f"'><img src=x data-probe='{XSS_PROBE_MARKER}'>",
    f"{XSS_PROBE_MARKER}<script>void(0)</script>",
)

SEARCH_PARAM_HINTS = ("s", "search", "q", "query", "keyword", "keywords", "term", "find")

SITEMAP_CANDIDATES = (
    "wp-sitemap.xml",
    "sitemap.xml",
    "sitemap_index.xml",
    "sitemap-index.xml",
)

CONTACT_PATH_PATTERN = re.compile(
    r"(?:^|[/?#_-])(?:contact(?:-us|_us)?|get-in-touch|reach-us|support|help|"
    r"about(?:-us|_us)?|kontakt|impressum|"
    r"تماس(?:-با-ما|-با|_با_ما)?|ارتباط|درباره(?:-ما|_ما)?|پشتیبانی)(?:[/?#_-]|$|\.)",
    re.I,
)

CONTACT_LINK_TEXT_PATTERN = re.compile(
    r"(contact\s*(?:us|me)?|get\s*in\s*touch|reach\s*(?:out|us)|customer\s*support|"
    r"support|help\s*center|about\s*us|"
    r"تماس\s*با\s*ما|ارتباط\s*با\s*ما|درباره\s*ما|پشتیبانی|تماس)",
    re.I,
)

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I)

EMAIL_IGNORE_DOMAINS = frozenset(
    {
        "example.com",
        "domain.com",
        "email.com",
        "wordpress.org",
        "w3.org",
        "schema.org",
        "gravatar.com",
        "sentry.io",
        "googleapis.com",
        "gstatic.com",
        "placeholder.com",
        "yourdomain.com",
        "sentry-next.wixpress.com",
        "wixpress.com",
    }
)

PERSIAN_DIGIT_MAP = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")

IRAN_AREA_CODES = (
    "11", "13", "17", "21", "23", "24", "25", "26", "28", "31", "34", "35", "38",
    "41", "44", "45", "51", "54", "56", "58", "61", "66", "74", "76", "77", "81",
    "83", "84", "86", "87", "88",
)

IRAN_MOBILE_PATTERN = re.compile(
    r"(?<!\d)(?:\+98|0098|98[\s\-]?)?0?9[\s\-]?\d{2}[\s\-]?\d{3}[\s\-]?\d{4}(?!\d)"
)

IRAN_LANDLINE_PATTERN = re.compile(
    r"(?<!\d)0(?:"
    + "|".join(IRAN_AREA_CODES)
    + r")[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)"
)

PERSIAN_ADDRESS_HINTS = re.compile(
    r"(?:آدرس|نشانی|address|موقعیت(?:\s*مکانی)?)\s*[:\-–]?\s*([^\n<]{15,250})",
    re.I,
)

WOOCOMMERCE_ADDRESS_PATTERN = re.compile(
    r'class="[^"]*woocommerce-store-address[^"]*"[^>]*>(.*?)</',
    re.I | re.S,
)

PERSIAN_CITY_ADDRESS_PATTERN = re.compile(
    r"((?:تهران|اصفهان|مشهد|شیراز|تبریز|کرج|قم|اهواز|کرمان|رشت|یزد|همدان|ارومیه|"
    r"زاهدان|کرمانشاه|خرم(?:آ|ا)باد|ساری|گرگان|بندر(?:عباس|انشهر)|قزوین|سنندج|"
    r"یاسوج|بجنورد|بوشهر|ایلام|سمنان|شهر(?:کرد|بو|ت|جدید)|کاشان|نجف(?:آ|ا)باد|"
    r"دزفول|مراغه|سبزوار)[^\n<]{8,120})"
)

SHOP_PATH_PATTERN = re.compile(
    r"(?:^|[/?#_-])(?:shop|store|my-account|checkout|cart|فروشگاه|سبد-?خرید|حساب-?کاربری)(?:[/?#_-]|$|\.)",
    re.I,
)

ADMIN_LOGIN_LINK_PATTERN = re.compile(
    r'href=["\']([^"\']*(?:wp-login|wp-admin|/login|sign-in|ورود|پنل(?:-|\s)?مدیریت)[^"\']*)["\']',
    re.I,
)

SOCIAL_PATTERNS = (
    ("Facebook", re.compile(r"https?://(?:www\.|m\.)?facebook\.com/[^\s\"'<>]+", re.I)),
    ("Instagram", re.compile(r"https?://(?:www\.)?instagram\.com/[^\s\"'<>]+", re.I)),
    ("Twitter/X", re.compile(r"https?://(?:www\.)?(?:twitter\.com|x\.com)/[^\s\"'<>]+", re.I)),
    ("LinkedIn", re.compile(r"https?://(?:www\.)?linkedin\.com/[^\s\"'<>]+", re.I)),
    ("YouTube", re.compile(r"https?://(?:www\.)?(?:youtube\.com|youtu\.be)/[^\s\"'<>]+", re.I)),
    ("Telegram", re.compile(r"https?://(?:t\.me|telegram\.me)/[^\s\"'<>]+", re.I)),
    ("WhatsApp", re.compile(r"https?://(?:wa\.me|api\.whatsapp\.com)/[^\s\"'<>]+", re.I)),
    ("TikTok", re.compile(r"https?://(?:www\.)?tiktok\.com/[^\s\"'<>]+", re.I)),
)

MAX_SITEMAP_URLS = 200
MAX_SITEMAP_FETCH_DEPTH = 2
MAX_CONTACT_PAGES = 5

POST_PATH_PATTERN = re.compile(
    r"(?:^|[/?#_-])(?:\d{4}/\d{2}/(?:\d{2}/)?|blog/|news/|article/|articles/|post/|posts/|"
    r"story/|stories/|mag/|magazine/)(?:[/?#_-]|$|\.)",
    re.I,
)

WOOCOMMERCE_PROBE_PATHS = (
    "shop/",
    "store/",
    "cart/",
    "checkout/",
    "my-account/",
    "product/",
)

MAX_ASSET_CRAWL_PAGES = 10
MAX_ASSET_CRAWL_POSTS = 4
MAX_ASSET_CRAWL_SHOP = 3
MAX_ASSET_CRAWL_INTERNAL = 3

ASSET_CRAWL_SKIP_PATTERN = re.compile(
    r"(?:wp-admin|wp-login|wp-json|xmlrpc|/feed/?$|/comments/|trackback|"
    r"\.(?:jpg|jpeg|png|gif|webp|pdf|zip|xml|rss|json|css|js)$)",
    re.I,
)


def parse_version(value):
    """Turn a version string like '6.4.2' into a comparable tuple (6, 4, 2).

    Non-numeric / missing segments are ignored so that string comparison
    pitfalls (e.g. '6.10' < '6.5') are avoided.
    """
    parts = re.findall(r"\d+", value or "")
    return tuple(int(p) for p in parts) if parts else None


class WordPressScanner:
    def __init__(
        self,
        target_url,
        log_callback=None,
        progress_callback=None,
        max_workers=20,
        timeout=8,
        proxies=None,
        scan_config=None,
    ):
        self.target_url = target_url.rstrip("/")
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self._component_lock = threading.Lock()
        self.timeout = timeout
        self.max_workers = max_workers
        self.proxies = proxies
        self.scan_config = self._normalize_scan_config(scan_config)
        self._homepage_response = None
        self._session_local = threading.local()
        self.session = self._build_session()
        self.results = {
            "url": self.target_url,
            "version": "Unknown",
            "is_wordpress": False,
            "vulnerabilities": [],
            "update_recommendations": [],
            "users": [],
            "plugins": [],
            "themes": [],
            "component_vulnerabilities": [],
            "core_version_status": None,
            "auth_surface": {"wp_admin": False, "xmlrpc": False},
            "stack": {
                "php_version": None,
                "web_server": None,
                "cdn": {"detected": False, "provider": None, "signals": []},
                "rest_api_exposure": {
                    "score": 0,
                    "max_score": REST_API_MAX_SCORE,
                    "grade": "F",
                    "checks": {},
                },
            },
            "search_forms": [],
            "injection_findings": [],
            "dynamic_analysis_findings": [],
            "site_intelligence": {
                "sitemap": {"found": False, "url": None, "urls": [], "total": 0},
                "contact_pages": [],
                "admin_login_urls": [],
                "contacts": {
                    "emails": [],
                    "phones": [],
                    "social_links": [],
                    "addresses": [],
                    "organization": None,
                },
                "sources": [],
            },
            "asset_crawl": {
                "pages_crawled": [],
                "plugins_discovered": 0,
                "themes_discovered": 0,
            },
            "duration": 0,
            "severity_counts": {k: 0 for k in SEVERITY_ORDER},
        }

    @staticmethod
    def _normalize_scan_config(scan_config):
        merged = copy.deepcopy(DEFAULT_SCAN_SETTINGS)
        cfg = scan_config or {}
        for section in ("injection", "vuln_lookup", "dynamic_analysis"):
            if section in cfg and isinstance(cfg[section], dict):
                merged[section].update(cfg[section])
        inj = merged["injection"]
        inj["max_forms"] = max(1, min(int(inj.get("max_forms") or 8), 30))
        dyn = merged["dynamic_analysis"]
        dyn["max_probes"] = max(1, min(int(dyn.get("max_probes") or 15), 50))
        dyn["delay_seconds"] = max(0.0, min(float(dyn.get("delay_seconds") or 0.5), 5.0))
        if dyn.get("min_severity") not in ("Critical", "High"):
            dyn["min_severity"] = "Critical"
        return merged

    def _build_session(self):
        session = requests.Session()
        encodings = "gzip, deflate"
        try:
            import brotli  # noqa: F401

            encodings = "gzip, deflate, br"
        except ImportError:
            pass
        session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
                ),
                "Accept-Encoding": encodings,
            }
        )
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504])
        pool_size = min(4, max(1, self.max_workers // 4))
        adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_size, pool_maxsize=pool_size)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        if self.proxies:
            session.proxies.update(self.proxies)
        return session

    def _get_session(self):
        """Thread-local HTTP session — safe for ThreadPoolExecutor workers."""
        session = getattr(self._session_local, "session", None)
        if session is None:
            session = self._build_session()
            self._session_local.session = session
        return session

    def log(self, message, type="info"):
        if self.log_callback:
            self.log_callback({"message": message, "type": type})

    def emit_progress(self, phase, **extra):
        if not self.progress_callback:
            return
        payload = {"phase": phase}
        payload.update(extra)
        self.progress_callback(payload)

    def get(self, path="", **kwargs):
        """GET helper that resolves relative paths and applies a default timeout."""
        url = urljoin(self.target_url + "/", path) if path else self.target_url
        kwargs.setdefault("timeout", self.timeout)
        return self._get_session().get(url, **kwargs)

    def scan(self):
        start = time.time()
        self.log(f"Starting deep scan for {self.target_url}...", "start")

        self.log("Fetching target homepage...")
        homepage = self._fetch_homepage()
        self.emit_progress("homepage", is_wordpress=self.results["is_wordpress"])

        self.log("Fingerprinting server stack (PHP, web server, CDN)...")
        self.detect_stack_fingerprint()
        self.emit_progress("stack", stack=self.results["stack"], is_wordpress=self.results["is_wordpress"])

        self.log("Detecting WordPress version...")
        self.check_version(homepage)
        self.emit_progress("version", version=self.results["version"])

        self.log("Enumerating users...")
        self.check_user_enumeration(homepage)
        self.emit_progress("users", users=list(self.results["users"]))

        self.log("Discovering sitemap, contact pages, and site owner information...")
        self.collect_site_intelligence(homepage)
        self.emit_progress(
            "site_intelligence",
            site_intelligence=self.results["site_intelligence"],
        )

        self.log("Checking wp-admin and XML-RPC exposure...")
        self.check_auth_surface()
        self.emit_progress(
            "auth",
            auth_surface=self.results["auth_surface"],
        )

        self.log("Discovering search fields and testing for SQLi/XSS...")
        self.check_search_injection(homepage)
        self.emit_progress(
            "injection",
            search_forms=list(self.results["search_forms"]),
            injection_findings=list(self.results["injection_findings"]),
        )

        self.log("Searching for sensitive files and misconfigurations...")
        self.check_logical_flaws()
        self.emit_progress("misconfig")

        self.log("Identifying plugins and themes...")
        self.detect_plugins_and_themes(homepage)
        self.emit_progress(
            "components",
            plugins=list(self.results["plugins"]),
            themes=list(self.results["themes"]),
            asset_crawl=self.results["asset_crawl"],
        )

        self._mark_security_plugin_stack()

        self.log("Checking for known vulnerabilities in components...")
        self.lookup_vulnerabilities()
        self.emit_progress(
            "vulnerabilities",
            version=self.results["version"],
            plugins=list(self.results["plugins"]),
            themes=list(self.results["themes"]),
            vulnerabilities=list(self.results["vulnerabilities"]),
            update_recommendations=list(self.results["update_recommendations"]),
            core_version_status=self.results.get("core_version_status"),
        )

        self.log("Running safe dynamic PoC verification for Critical RCE/SQLi...")
        self.run_dynamic_analysis()
        self.emit_progress(
            "dynamic",
            vulnerabilities=list(self.results["vulnerabilities"]),
            dynamic_analysis_findings=list(self.results["dynamic_analysis_findings"]),
        )

        self._finalize()
        self.results["duration"] = round(time.time() - start, 2)
        vuln_count = len(self.results["vulnerabilities"])
        update_count = len(self.results["update_recommendations"])
        summary = f"{vuln_count} security finding(s)"
        if update_count:
            summary += f", {update_count} update recommendation(s)"
        self.log(
            f"Scan completed in {self.results['duration']}s — {summary}.",
            "end",
        )
        return self.results

    def _fetch_homepage(self):
        try:
            res = self.get()
            self._homepage_response = res
            text = res.text
            if "wp-content" in text or "wp-includes" in text or "/wp-json" in text:
                self.results["is_wordpress"] = True
                self.log("Confirmed WordPress fingerprint on target.", "success")
            else:
                self.log("Target does not look like WordPress (scanning anyway).", "warning")
            return text
        except Exception as e:
            self.log(f"Could not reach target homepage: {e}", "error")
            self._homepage_response = None
            return ""

    def check_version(self, text):
        try:
            match = re.search(r'content="WordPress ([^"]+)"', text)
            if match:
                self.results["version"] = match.group(1).strip()
                self.log(f"Found version {self.results['version']} via Meta Generator", "success")
                return

            wp_versions = WP_INCLUDES_VERSION.findall(text or "")
            if wp_versions:
                self.results["version"] = Counter(wp_versions).most_common(1)[0][0]
                self.log(
                    f"Estimated version {self.results['version']} from wp-includes assets",
                    "info",
                )
                return

            r = self.get("readme.html")
            if r.status_code == 200 and not self._is_html_error_page(r.text):
                rm = re.search(r"Version\s+([0-9.]+)", r.text)
                if rm:
                    self.results["version"] = rm.group(1)
                    self.log(f"Version {self.results['version']} leaked via readme.html", "warning")
        except Exception as e:
            self.log(f"Error during version check: {e}", "error")

    def detect_stack_fingerprint(self):
        res = self._homepage_response
        headers = self._normalize_response_headers(res)

        stack = {
            "php_version": None,
            "web_server": None,
            "cdn": {"detected": False, "provider": None, "signals": []},
        }

        powered_by = headers.get("x-powered-by", "")
        php_match = re.search(r"PHP/([\d.]+)", powered_by, re.I)
        if php_match:
            stack["php_version"] = php_match.group(1)
        else:
            for value in headers.values():
                match = re.search(r"PHP/([\d.]+)", value, re.I)
                if match:
                    stack["php_version"] = match.group(1)
                    break

        server = headers.get("server", "").strip()
        if server:
            stack["web_server"] = server

        cdn_signals = []
        cdn_provider = None
        for provider, header_names in CDN_HEADER_RULES:
            for header_name in header_names:
                if header_name in headers:
                    cdn_signals.append(f"{header_name}: {headers[header_name]}")
                    cdn_provider = provider

        for header_name, value in headers.items():
            for pattern, provider in CDN_SERVER_PATTERNS:
                if pattern.search(value):
                    cdn_signals.append(f"{header_name}: {value}")
                    cdn_provider = provider

        via = headers.get("via", "")
        if via and not cdn_provider:
            if "cloudfront" in via.lower():
                cdn_provider = "Amazon CloudFront"
                cdn_signals.append(f"via: {via}")
            elif "cache" in via.lower() or "cdn" in via.lower():
                cdn_signals.append(f"via: {via}")

        if cdn_provider:
            stack["cdn"] = {
                "detected": True,
                "provider": cdn_provider,
                "signals": list(dict.fromkeys(cdn_signals))[:5],
            }

        self.results["stack"] = stack

        if stack["php_version"]:
            self.log(f"Detected PHP {stack['php_version']}", "info")
        else:
            self.log("PHP version not disclosed in response headers.", "info")

        if stack["web_server"]:
            self.log(f"Detected web server: {stack['web_server']}", "info")
        else:
            self.log("Web server banner not disclosed.", "info")

        if stack["cdn"]["detected"]:
            self.log(
                f"CDN detected: {stack['cdn']['provider']} "
                f"({', '.join(stack['cdn']['signals'][:2])})",
                "warning",
            )
        else:
            self.log("No CDN fingerprint detected.", "info")

        self.check_rest_api_exposure()

    @staticmethod
    def _normalize_response_headers(response):
        if response is None:
            return {}
        return {k.lower(): v for k, v in response.headers.items()}

    @staticmethod
    def _security_grade(score, max_score):
        if max_score <= 0:
            return "F"
        pct = (score / max_score) * 100
        if pct >= 90:
            return "A"
        if pct >= 80:
            return "B"
        if pct >= 70:
            return "C"
        if pct >= 60:
            return "D"
        return "F"

    def _evaluate_rest_api_exposure(self):
        max_score = REST_API_MAX_SCORE
        try:
            res = self.get("wp-json/wp/v2/")
            content_type = (res.headers.get("Content-Type") or "").lower()
            if res.status_code == 200 and content_type.startswith("application/json"):
                payload = res.json()
                if isinstance(payload, dict) and any(key in payload for key in ("namespace", "routes", "name")):
                    routes = payload.get("routes") or {}
                    route_count = len(routes) if isinstance(routes, dict) else 0
                    return {
                        "accessible": True,
                        "status_code": res.status_code,
                        "score": 0,
                        "max_score": max_score,
                        "status": "open",
                        "route_count": route_count,
                        "note": (
                            "Unauthenticated access to /wp-json/wp/v2/ exposes the REST API route map "
                            "for reconnaissance and monitoring."
                        ),
                    }

            if res.status_code in (401, 403):
                return {
                    "accessible": False,
                    "status_code": res.status_code,
                    "score": max_score,
                    "max_score": max_score,
                    "status": "restricted",
                    "note": f"REST API root returned HTTP {res.status_code} without authentication.",
                }

            return {
                "accessible": False,
                "status_code": res.status_code,
                "score": max_score,
                "max_score": max_score,
                "status": "blocked",
                "note": f"REST API root not publicly exposed (HTTP {res.status_code}).",
            }
        except Exception as exc:
            return {
                "accessible": None,
                "status_code": None,
                "score": 0,
                "max_score": max_score,
                "status": "unknown",
                "note": f"Could not probe REST API root: {exc}",
            }

    def check_rest_api_exposure(self):
        self.log("Probing public REST API exposure...")

        check = self._evaluate_rest_api_exposure()
        score = check.get("score", 0)
        max_score = check.get("max_score", REST_API_MAX_SCORE)
        grade = self._security_grade(score, max_score)

        self.results["stack"]["rest_api_exposure"] = {
            "score": score,
            "max_score": max_score,
            "grade": grade,
            "checks": {"rest_api_root": check},
        }

        self.log(
            f"REST API exposure score: {score}/{max_score} (grade {grade})",
            "success" if score >= max_score * 0.8 else "warning" if score >= max_score * 0.5 else "error",
        )

        if check.get("accessible") is True:
            self.log(f"REST API root is publicly accessible — {check.get('note')}", "warning")
        elif check.get("accessible") is False:
            self.log(f"REST API root restricted — {check.get('note')}", "success")
        else:
            self.log(f"REST API root probe inconclusive — {check.get('note')}", "info")

        if check.get("accessible") is True:
            self.add_vuln(
                "Public WordPress REST API Root",
                "Low",
                check["note"],
            )

    def _mark_security_plugin_stack(self):
        found = []
        for plugin in self.results.get("plugins") or []:
            slug = (plugin.get("slug") or "").lower()
            if slug in SECURITY_PLUGIN_SLUGS:
                found.append(slug)

        self.results["stack"]["security_plugin"] = {
            "detected": bool(found),
            "slugs": found,
        }
        if found:
            self.log(
                f"Security plugin(s) detected: {', '.join(found)}",
                "info",
            )

    def _parse_tag_attrs(self, tag_content):
        attrs = {}
        for match in re.finditer(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(["\'])(.*?)\2', tag_content):
            attrs[match.group(1).lower()] = match.group(3)
        return attrs

    def _same_origin(self, url):
        target = urlparse(self.target_url)
        parsed = urlparse(urljoin(self.target_url + "/", url or "/"))
        if not parsed.netloc:
            return True
        return parsed.netloc.lower() == target.netloc.lower()

    def _is_search_input(self, attrs):
        input_type = (attrs.get("type") or "text").lower()
        if input_type in ("hidden", "submit", "button", "image", "file", "checkbox", "radio", "password"):
            return False
        name = (attrs.get("name") or "").lower()
        input_id = (attrs.get("id") or "").lower()
        placeholder = (attrs.get("placeholder") or "").lower()
        if input_type == "search":
            return bool(name or input_id)
        hints = SEARCH_PARAM_HINTS + ("search",)
        return any(h in name or h in input_id or h in placeholder for h in hints)

    def _discover_search_forms(self, html):
        forms = []
        seen = set()

        def add_form(method, action, param, label):
            key = (method.upper(), action, param)
            if key in seen:
                return
            seen.add(key)
            forms.append(
                {
                    "method": method.upper(),
                    "action": action,
                    "param": param,
                    "label": label,
                }
            )

        add_form("GET", self.target_url + "/", "s", "WordPress search (?s=)")

        for form_match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html or "", re.I | re.S):
            form_attrs = self._parse_tag_attrs(form_match.group(1))
            method = (form_attrs.get("method") or "get").upper()
            action = form_attrs.get("action") or self.target_url + "/"
            if not self._same_origin(action):
                continue

            for input_match in re.finditer(r"<input\b([^>]*)/?>", form_match.group(2), re.I):
                attrs = self._parse_tag_attrs(input_match.group(1))
                if not self._is_search_input(attrs):
                    continue
                param = attrs.get("name") or attrs.get("id")
                if not param:
                    continue
                label = f"Form search field ({param})"
                add_form(method, action, param, label)

        for input_match in re.finditer(r"<input\b([^>]*)/?>", html or "", re.I):
            attrs = self._parse_tag_attrs(input_match.group(1))
            if not self._is_search_input(attrs):
                continue
            param = attrs.get("name") or attrs.get("id")
            if not param:
                continue
            add_form("GET", self.target_url + "/", param, f"Standalone search input ({param})")

        return forms

    def _request_with_param(self, form, value):
        method = form["method"]
        action = form["action"]
        param = form["param"]
        url = urljoin(self.target_url + "/", action)

        if method == "GET":
            parsed = urlparse(url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            query[param] = [value]
            flat_query = []
            for key, values in query.items():
                for item in values:
                    flat_query.append((key, item))
            target = parsed._replace(query=urlencode(flat_query))
            return self._get_session().get(target.geturl(), timeout=self.timeout)

        data = {param: value}
        return self._get_session().post(url, data=data, timeout=self.timeout)

    def _detect_sql_injection(self, baseline_text, response_text):
        for pattern in SQL_ERROR_PATTERNS:
            if pattern.search(response_text or "") and not pattern.search(baseline_text or ""):
                return pattern.pattern
        return None

    def _detect_reflected_xss(self, payload, response_text):
        if XSS_PROBE_MARKER not in payload:
            return False
        body = response_text or ""
        if XSS_PROBE_MARKER not in body:
            return False
        escaped_marker = XSS_PROBE_MARKER.replace("<", "&lt;").replace(">", "&gt;")
        return escaped_marker not in body

    def check_search_injection(self, homepage):
        inj_cfg = self.scan_config.get("injection", {})
        if not inj_cfg.get("enabled", True):
            self.log("Search injection testing disabled in settings.", "info")
            return

        forms = self._discover_search_forms(homepage)
        max_forms = inj_cfg.get("max_forms", 8)
        forms = forms[:max_forms]
        self.results["search_forms"] = forms

        if not forms:
            self.log("No search fields discovered.", "info")
            return

        self.log(f"Found {len(forms)} search field(s). Testing SQLi/XSS...", "info")
        test_sql = inj_cfg.get("test_sql", True)
        test_xss = inj_cfg.get("test_xss", True)
        benign = "wpguardbenignscan123"

        for form in forms:
            label = form["label"]
            try:
                baseline = self._request_with_param(form, benign)
                baseline_text = baseline.text
            except Exception as exc:
                self.log(f"Could not reach search endpoint '{label}': {exc}", "warning")
                continue

            if test_sql:
                for payload in SQL_PAYLOADS:
                    try:
                        res = self._request_with_param(form, payload)
                        error_pattern = self._detect_sql_injection(baseline_text, res.text)
                        if error_pattern:
                            finding = {
                                "type": "sqli",
                                "form": label,
                                "param": form["param"],
                                "payload": payload,
                                "evidence": "Database error pattern in response",
                            }
                            self.results["injection_findings"].append(finding)
                            self.add_vuln(
                                f"Possible SQL Injection: {form['param']}",
                                "High",
                                (
                                    f"Search parameter '{form['param']}' on {label} triggered a SQL error "
                                    f"with payload `{payload}`. Manual verification recommended."
                                ),
                            )
                            self.log(
                                f"Possible SQLi on '{form['param']}' ({label}) with payload `{payload}`",
                                "warning",
                            )
                            break
                    except Exception:
                        continue

            if test_xss:
                for payload in XSS_PAYLOADS:
                    try:
                        res = self._request_with_param(form, payload)
                        if self._detect_reflected_xss(payload, res.text):
                            finding = {
                                "type": "xss",
                                "form": label,
                                "param": form["param"],
                                "payload": payload,
                                "evidence": "Probe marker reflected without encoding",
                            }
                            self.results["injection_findings"].append(finding)
                            self.add_vuln(
                                f"Reflected XSS: {form['param']}",
                                "High",
                                (
                                    f"Search parameter '{form['param']}' on {label} reflects unsanitized input. "
                                    f"Payload probe was echoed in the response."
                                ),
                            )
                            self.log(
                                f"Possible reflected XSS on '{form['param']}' ({label})",
                                "warning",
                            )
                            break
                    except Exception:
                        continue

        if not self.results["injection_findings"]:
            self.log("No SQLi/XSS indicators found on discovered search fields.", "success")

    def _strip_html(self, text):
        return re.sub(r"<[^>]+>", "", text or "").strip()

    @staticmethod
    def _normalize_digits(text):
        return (text or "").translate(PERSIAN_DIGIT_MAP)

    @staticmethod
    def _file_extension(name):
        lowered = (name or "").lower()
        dot = lowered.rfind(".")
        if dot <= 0:
            return ""
        return lowered[dot:]

    def _is_image_file(self, name):
        return self._file_extension(name) in IMAGE_EXTENSIONS

    def _normalize_iranian_phone(self, raw):
        digits = re.sub(r"\D", "", self._normalize_digits(raw))
        if not digits:
            return None

        if digits.startswith("0098"):
            digits = "0" + digits[4:]
        elif digits.startswith("98") and len(digits) >= 12:
            digits = "0" + digits[2:]
        elif len(digits) == 10 and digits.startswith("9"):
            digits = "0" + digits

        if len(digits) == 11 and digits.startswith("09"):
            return f"{digits[:4]} {digits[4:7]} {digits[7:]}"

        if len(digits) == 11 and digits.startswith("0"):
            area = digits[1:3]
            if area in IRAN_AREA_CODES:
                return f"{digits[:3]} {digits[3:7]} {digits[7:]}"
        return None

    def _extract_iranian_phones(self, text):
        phones = set()
        normalized_text = self._normalize_digits(text or "")

        for pattern in (IRAN_MOBILE_PATTERN, IRAN_LANDLINE_PATTERN):
            for match in pattern.finditer(normalized_text):
                formatted = self._normalize_iranian_phone(match.group(0))
                if formatted:
                    phones.add(formatted)

        for match in re.finditer(r'href\s*=\s*["\']tel:([^"\']+)', text or "", re.I):
            formatted = self._normalize_iranian_phone(match.group(1))
            if formatted:
                phones.add(formatted)

        return phones

    def _extract_html_addresses(self, html, plain):
        addresses = set()

        for match in PERSIAN_ADDRESS_HINTS.finditer(plain):
            line = match.group(1).strip(" \t\r\n-–:،,")
            if len(line) >= 10:
                addresses.add(line[:250])

        for match in PERSIAN_CITY_ADDRESS_PATTERN.finditer(plain):
            line = match.group(1).strip(" \t\r\n-–:،,")
            if len(line) >= 10:
                addresses.add(line[:250])

        for match in WOOCOMMERCE_ADDRESS_PATTERN.finditer(html or ""):
            line = self._strip_html(match.group(1)).strip(" \t\r\n-–:،,")
            if len(line) >= 10:
                addresses.add(line[:250])

        for match in re.finditer(
            r"<address\b[^>]*>(.*?)</address>",
            html or "",
            re.I | re.S,
        ):
            line = self._strip_html(match.group(1)).strip(" \t\r\n-–:،,")
            if len(line) >= 10:
                addresses.add(line[:250])

        return addresses

    def _discover_admin_login_urls(self, homepage):
        found = []
        seen = set()

        def add(url, source):
            full = urljoin(self.target_url + "/", (url or "").strip())
            if not self._same_origin(full):
                return
            normalized = full.rstrip("/")
            if normalized in seen:
                return
            seen.add(normalized)
            parsed = urlparse(full)
            found.append(
                {
                    "url": full,
                    "path": parsed.path or "/",
                    "source": source,
                }
            )

        for path in ("wp-login.php", "wp-admin/", "login/", "admin/"):
            try:
                res = self.get(path, allow_redirects=True, timeout=5)
                final = (res.url or "").rstrip("/")
                body = (res.text or "")[:4000].lower()
                if res.status_code not in (200, 301, 302, 403):
                    continue
                if any(marker in final.lower() for marker in ("wp-login", "wp-admin", "login")):
                    add(final, f"probe:{path}")
                elif 'name="log"' in body or "wp-login" in body or "password" in body or "ورود" in body:
                    add(final, f"probe:{path}")
            except Exception:
                continue

        for match in re.finditer(r"<form\b([^>]*)>", homepage or "", re.I):
            attrs = self._parse_tag_attrs(match.group(1))
            action = (attrs.get("action") or "").strip()
            if not action:
                continue
            action_lower = action.lower()
            if any(token in action_lower for token in ("login", "wp-login", "wp-admin", "ورود")):
                add(action, "login_form")

        for match in ADMIN_LOGIN_LINK_PATTERN.finditer(homepage or ""):
            add(match.group(1), "homepage_link")

        return found

    def collect_site_intelligence(self, homepage):
        intel = self.results["site_intelligence"]
        sitemap_urls, sitemap_source = self._discover_sitemap()
        intel["sitemap"] = {
            "found": bool(sitemap_urls),
            "url": sitemap_source,
            "urls": sitemap_urls[:MAX_SITEMAP_URLS],
            "total": len(sitemap_urls),
        }
        if sitemap_source:
            self.log(f"Sitemap found at {sitemap_source} ({len(sitemap_urls)} URLs)", "success")
        else:
            self.log("No sitemap discovered.", "info")

        contact_pages = self._find_contact_pages(homepage, sitemap_urls)
        intel["contact_pages"] = contact_pages
        if contact_pages:
            self.log(f"Found {len(contact_pages)} contact-related page(s)", "success")
        else:
            self.log("No contact page identified.", "info")

        admin_urls = self._discover_admin_login_urls(homepage)
        intel["admin_login_urls"] = admin_urls
        if admin_urls:
            primary = admin_urls[0]
            self.results["auth_surface"]["login_url"] = primary.get("url")
            self.results["auth_surface"]["login_path"] = primary.get("path")
            self.log(
                f"Admin/login surface found: {primary.get('path') or primary.get('url')} "
                f"({len(admin_urls)} URL(s))",
                "success",
            )
        else:
            self.log("No admin/login URL discovered.", "info")

        pages_to_scan = [(self.target_url + "/", "homepage", homepage)]
        for page in contact_pages[:MAX_CONTACT_PAGES]:
            if page.get("fetched"):
                continue
            try:
                parsed = urlparse(page["url"])
                if not self._same_origin(page["url"]):
                    continue
                rel_path = parsed.path.lstrip("/")
                if parsed.query:
                    rel_path = f"{rel_path}?{parsed.query}"
                res = self.get(rel_path)
                if res.status_code == 200:
                    page["fetched"] = True
                    pages_to_scan.append((page["url"], page.get("source", "contact"), res.text))
            except Exception:
                continue

        for url, source, html in pages_to_scan:
            extracted = self._extract_contacts_from_html(html, url)
            if any(
                extracted.get(k)
                for k in ("emails", "phones", "social_links", "addresses", "organization")
            ):
                intel["sources"].append({"url": url, "source": source, **extracted})
            self._merge_contacts(intel["contacts"], extracted)

        counts = intel["contacts"]
        found = (
            len(counts["emails"])
            + len(counts["phones"])
            + len(counts["social_links"])
            + len(counts["addresses"])
            + (1 if counts["organization"] else 0)
            + len(intel.get("admin_login_urls") or [])
        )
        if found:
            self.log(
                f"Collected site info: {len(counts['emails'])} email(s), "
                f"{len(counts['phones'])} phone(s), {len(counts['social_links'])} social link(s)",
                "success",
            )
        else:
            self.log("No contact or owner information extracted from public pages.", "info")

    def _discover_sitemap(self):
        candidates = []
        seen = set()

        try:
            robots = self.get("robots.txt")
            if robots.status_code == 200:
                for line in robots.text.splitlines():
                    if line.lower().startswith("sitemap:"):
                        url = line.split(":", 1)[1].strip()
                        if url and url not in seen:
                            seen.add(url)
                            candidates.append(url)
        except Exception:
            pass

        for path in SITEMAP_CANDIDATES:
            url = urljoin(self.target_url + "/", path)
            if url not in seen:
                seen.add(url)
                candidates.append(url)

        for candidate in candidates:
            urls = self._fetch_sitemap_urls(candidate, depth=0)
            if urls:
                return urls, candidate
        return [], None

    def _fetch_sitemap_urls(self, sitemap_url, depth=0):
        if depth > MAX_SITEMAP_FETCH_DEPTH:
            return []

        try:
            res = self._get_session().get(sitemap_url, timeout=self.timeout)
            if res.status_code != 200:
                return []
            content = res.text.strip()
            if not content:
                return []
        except Exception:
            return []

        locs = self._parse_sitemap_locs(content)
        if not locs:
            return []

        sub_sitemaps = [loc for loc in locs if loc.lower().endswith(".xml")]
        page_urls = [loc for loc in locs if loc not in sub_sitemaps]

        if sub_sitemaps and len(page_urls) < 5:
            for sub in sub_sitemaps[:10]:
                page_urls.extend(self._fetch_sitemap_urls(sub, depth + 1))
                if len(page_urls) >= MAX_SITEMAP_URLS:
                    break

        unique = []
        seen = set()
        for url in page_urls:
            if url not in seen:
                seen.add(url)
                unique.append(url)
            if len(unique) >= MAX_SITEMAP_URLS:
                break
        return unique

    @staticmethod
    def _parse_sitemap_locs(content):
        locs = []
        try:
            root = ET.fromstring(content)
            for elem in root.iter():
                if elem.tag.endswith("loc") and elem.text:
                    locs.append(elem.text.strip())
        except ET.ParseError:
            for match in re.finditer(r"<loc>\s*(.*?)\s*</loc>", content, re.I | re.S):
                locs.append(match.group(1).strip())
        return locs

    def _find_contact_pages(self, homepage, sitemap_urls):
        pages = []
        seen_urls = set()

        def add_page(url, source, title=None, allow_shop=False):
            full = urljoin(self.target_url + "/", url)
            if not self._same_origin(full):
                return
            normalized = full.rstrip("/")
            if normalized in seen_urls:
                return
            path = urlparse(full).path or "/"
            is_contact = CONTACT_PATH_PATTERN.search(path)
            is_shop = allow_shop or SHOP_PATH_PATTERN.search(path)
            if not is_contact and not is_shop and source != "link_text":
                return
            seen_urls.add(normalized)
            pages.append({"url": full, "source": source, "title": title, "fetched": False})

        for url in sitemap_urls:
            path = urlparse(url).path or ""
            if CONTACT_PATH_PATTERN.search(path):
                add_page(url, "sitemap")
            elif SHOP_PATH_PATTERN.search(path):
                add_page(url, "sitemap", allow_shop=True)

        for match in re.finditer(r"<a\b([^>]*)>(.*?)</a>", homepage or "", re.I | re.S):
            attrs = self._parse_tag_attrs(match.group(1))
            href = (attrs.get("href") or "").strip()
            if not href or href.startswith("#") or href.lower().startswith("javascript:"):
                continue
            link_text = self._strip_html(match.group(2))
            path = urlparse(urljoin(self.target_url + "/", href)).path or ""
            if CONTACT_PATH_PATTERN.search(path) or CONTACT_LINK_TEXT_PATTERN.search(link_text):
                add_page(href, "link_text", title=link_text[:120] or None)
            elif SHOP_PATH_PATTERN.search(path):
                add_page(href, "shop_link", title=link_text[:120] or None, allow_shop=True)

        try:
            res = self.get("wp-json/wp/v2/pages", params={"search": "contact", "per_page": 10})
            if res.status_code == 200 and res.headers.get("Content-Type", "").startswith("application/json"):
                for page in res.json():
                    link = (page.get("link") or "").strip()
                    title = (page.get("title", {}) or {}).get("rendered") or ""
                    title = self._strip_html(title)
                    slug = (page.get("slug") or "").lower()
                    if link and (CONTACT_PATH_PATTERN.search(slug) or CONTACT_LINK_TEXT_PATTERN.search(title)):
                        add_page(link, "rest_api", title=title or None)
        except Exception:
            pass

        return pages

    def _extract_contacts_from_html(self, html, source_url):
        text = html or ""
        plain = self._strip_html(text)

        emails = set()
        for match in EMAIL_PATTERN.finditer(text + " " + plain):
            email = match.group(0).lower().rstrip(".")
            domain = email.split("@")[-1]
            if domain in EMAIL_IGNORE_DOMAINS:
                continue
            if any(email.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")):
                continue
            emails.add(email)
        for match in re.finditer(r'href\s*=\s*["\']mailto:([^"\'?\s>]+)', text, re.I):
            email = match.group(1).split("?")[0].strip().lower()
            domain = email.split("@")[-1] if "@" in email else ""
            if domain and domain not in EMAIL_IGNORE_DOMAINS:
                emails.add(email)

        phones = self._extract_iranian_phones(plain + " " + text)

        social_links = []
        seen_social = set()
        for platform, pattern in SOCIAL_PATTERNS:
            for match in pattern.finditer(text):
                url = match.group(0).rstrip("'\")\\>,.")
                if url not in seen_social:
                    seen_social.add(url)
                    social_links.append({"platform": platform, "url": url})

        addresses = set()
        organization = None

        org_holder = {"name": None}
        for block in re.finditer(
            r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
            text,
            re.I | re.S,
        ):
            try:
                data = json.loads(block.group(1).strip())
            except (json.JSONDecodeError, ValueError):
                continue
            self._extract_schema_contacts(data, addresses, org_holder)
            if org_holder["name"] and not organization:
                organization = org_holder["name"]

        if not organization:
            og_site = re.search(
                r'<meta\s[^>]*property=["\']og:site_name["\'][^>]*content=["\']([^"\']+)',
                text,
                re.I,
            )
            if og_site:
                organization = og_site.group(1).strip()

        addresses.update(self._extract_html_addresses(text, plain))

        return {
            "emails": sorted(emails),
            "phones": sorted(phones),
            "social_links": social_links,
            "addresses": sorted(addresses),
            "organization": organization,
        }

    def _extract_schema_contacts(self, data, addresses, org_holder):
        if isinstance(data, list):
            for item in data:
                self._extract_schema_contacts(item, addresses, org_holder)
            return
        if not isinstance(data, dict):
            return

        schema_type = data.get("@type", "")
        if isinstance(schema_type, list):
            schema_type = " ".join(schema_type)

        if any(t in str(schema_type) for t in ("Organization", "LocalBusiness", "Store", "Person")):
            name = data.get("name") or data.get("legalName")
            if name and not org_holder.get("name"):
                org_holder["name"] = str(name).strip()

        addr = data.get("address")
        if isinstance(addr, dict):
            parts = [
                addr.get("streetAddress"),
                addr.get("addressLocality"),
                addr.get("addressRegion"),
                addr.get("postalCode"),
                addr.get("addressCountry"),
            ]
            line = ", ".join(p for p in parts if p)
            if line:
                addresses.add(line)
        elif isinstance(addr, str) and addr.strip():
            addresses.add(addr.strip())

        for key in ("@graph", "department", "subOrganization", "parentOrganization"):
            nested = data.get(key)
            if nested:
                self._extract_schema_contacts(nested, addresses, org_holder)

    @staticmethod
    def _merge_contacts(target, extracted):
        for email in extracted.get("emails") or []:
            if email not in target["emails"]:
                target["emails"].append(email)
        for phone in extracted.get("phones") or []:
            if phone not in target["phones"]:
                target["phones"].append(phone)
        for addr in extracted.get("addresses") or []:
            if addr not in target["addresses"]:
                target["addresses"].append(addr)
        for link in extracted.get("social_links") or []:
            if not any(existing["url"] == link["url"] for existing in target["social_links"]):
                target["social_links"].append(link)
        if extracted.get("organization") and not target["organization"]:
            target["organization"] = extracted["organization"]

    def _user_key(self, username):
        return (username or "").strip().lower()

    def _find_user_index(self, username):
        key = self._user_key(username)
        if not key:
            return -1
        for i, entry in enumerate(self.results["users"]):
            existing = entry.get("username", entry) if isinstance(entry, dict) else entry
            if self._user_key(existing) == key:
                return i
        return -1

    def _make_user_entry(self, username, source="unknown", **fields):
        username = (username or "").strip()
        if not username:
            return None
        entry = {
            "username": username,
            "source": source,
            "name": fields.get("name"),
            "description": fields.get("description"),
            "profile_url": fields.get("profile_url"),
            "avatar": fields.get("avatar"),
            "id": fields.get("id"),
        }
        return {k: v for k, v in entry.items() if v is not None or k in ("username", "source")}

    def _add_user(self, username, source="unknown", **fields):
        username = (username or "").strip()
        if not username:
            return False

        entry = self._make_user_entry(username, source=source, **fields)
        idx = self._find_user_index(username)

        if idx >= 0:
            existing = self.results["users"][idx]
            if not isinstance(existing, dict):
                existing = self._make_user_entry(existing, source="unknown")
            merged = dict(existing)
            for key in ("name", "description", "profile_url", "avatar", "id"):
                if entry.get(key):
                    merged[key] = entry[key]
            if source == "rest_api" or entry.get("source") == "rest_api":
                merged["source"] = "rest_api"
            self.results["users"][idx] = merged
            return False

        self.results["users"].append(entry)
        return True

    def check_user_enumeration(self, homepage):
        self.log("Testing REST API for user enumeration...")
        try:
            res = self.get("wp-json/wp/v2/users")
            if res.status_code == 200 and res.headers.get("Content-Type", "").startswith("application/json"):
                for u in res.json():
                    avatar_urls = u.get("avatar_urls") or {}
                    avatar = avatar_urls.get("96") or avatar_urls.get("48") or avatar_urls.get("24")
                    description = self._strip_html(u.get("description"))
                    name = (u.get("name") or "").strip() or None
                    profile_url = (u.get("link") or "").strip() or None
                    self._add_user(
                        u.get("slug"),
                        source="rest_api",
                        id=u.get("id"),
                        name=name,
                        description=description or None,
                        profile_url=profile_url,
                        avatar=avatar,
                    )
                rest_users = [u for u in self.results["users"] if isinstance(u, dict) and u.get("source") == "rest_api"]
                if rest_users:
                    self.log(f"Found {len(rest_users)} users via REST API", "success")
                    self.add_vuln(
                        "REST API User Enumeration",
                        "Medium",
                        "Public access to /wp-json/wp/v2/users allows listing all registered users.",
                    )
        except Exception:
            pass

        self.log("Testing Author Archive fallback (?author=n)...")

        def probe_author(i):
            try:
                res = self.get(f"?author={i}", allow_redirects=True, timeout=5)
                if res.status_code == 200 and "/author/" in res.url:
                    return res.url.split("/author/")[-1].strip("/")
            except Exception:
                return None
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for user in ex.map(probe_author, range(1, 11)):
                if self._add_user(user, source="author"):
                    self.log(f"Discovered user '{user}' via author fallback", "success")

        self.log("Testing oEmbed discovery...")
        try:
            oembed_url = re.search(r'href="([^"]*?/wp-json/oembed/1\.0/embed\?url=[^"]*?)"', homepage)
            if oembed_url:
                oe_res = self._get_session().get(oembed_url.group(1).replace("&#038;", "&"), timeout=5)
                if oe_res.status_code == 200:
                    if self._add_user(oe_res.json().get("author_name"), source="oembed"):
                        self.log("Discovered user via oEmbed", "success")
        except Exception:
            pass

        if self.results["users"]:
            self.add_vuln(
                "User Enumeration Possible",
                "Medium",
                f"Total of {len(self.results['users'])} usernames extracted. This can help attackers target login attempts.",
            )

    def _is_wp_admin_reachable(self):
        try:
            res = self.get("wp-admin/", allow_redirects=True, timeout=5)
            final_url = (res.url or "").lower()
            if res.status_code in (200, 301, 302, 403) and (
                "wp-admin" in final_url or "wp-login" in final_url
            ):
                return True
        except Exception:
            pass

        try:
            res = self.get("wp-login.php", timeout=5)
            if res.status_code == 200 and len(res.content) > 100:
                body = res.text.lower()
                if "wp-login" in body or 'name="log"' in body or "log in" in body:
                    return True
        except Exception:
            pass
        return False

    def _is_xmlrpc_enabled(self):
        try:
            res = self.get("xmlrpc.php", timeout=5)
            if res.status_code != 200 or len(res.content) < 20:
                return False
            body = res.text
            if "XML-RPC server accepts POST requests" in body:
                return True
            content_type = res.headers.get("Content-Type", "").lower()
            return "html" not in content_type
        except Exception:
            return False

    def check_auth_surface(self):
        wp_admin_open = self._is_wp_admin_reachable()
        xmlrpc_open = self._is_xmlrpc_enabled()
        self.results["auth_surface"] = {"wp_admin": wp_admin_open, "xmlrpc": xmlrpc_open}

        if wp_admin_open:
            self.log("wp-admin / wp-login.php is reachable.", "warning")
            self.add_vuln(
                "wp-admin Accessible",
                "Medium",
                "The WordPress admin login surface is publicly reachable at /wp-admin/ or /wp-login.php.",
            )
        else:
            self.log("wp-admin login surface not reachable.", "info")

        if xmlrpc_open:
            self.log("xmlrpc.php is enabled and reachable.", "warning")
        else:
            self.log("xmlrpc.php is not reachable or disabled.", "info")

    def check_logical_flaws(self):
        checks = [
            ("xmlrpc.php", "XML-RPC Enabled", "Medium", "Can be abused for automated attacks or DDoS reflection."),
            ("wp-config.php.bak", "Backup Config File", "Critical", "Contains database credentials!"),
            ("wp-config.php.swp", "Vim Swap File", "Critical", "May leak source code of config."),
            ("wp-config.php~", "Temporary Config File", "Critical", "May leak source code of config."),
            (".env", "Environment File", "Critical", "Exposes secrets and API keys."),
            (".git/config", "Git Repository", "High", "Full source code exposure possible."),
            (".ssh/id_rsa", "Private SSH Key", "Critical", "Server access exposure!"),
            ("wp-content/debug.log", "Debug Log", "Medium", "May contain sensitive error data."),
            ("wp-links-opml.php", "OPML Leak", "Low", "Might leak internal metadata."),
            ("readme.html", "Default Readme", "Low", "Exposes WordPress version and installation details."),
            ("license.txt", "Default License", "Low", "Information disclosure."),
            ("wp-login.php", "Login Page Accessible", "Info", "Public login entry point."),
            ("wp-admin/install.php", "Installer Script", "High", "If not deleted, could allow re-installation."),
            ("wp-content/uploads/php.ini", "Custom PHP Config", "Medium", "Potential configuration override."),
            (".htaccess.bak", "Htaccess Backup", "Medium", "Exposes server configuration."),
        ]

        def check_path(item):
            path, name, sev, desc = item
            try:
                res = self.get(path, timeout=5)
                if res.status_code == 200 and len(res.content) > 100:
                    content_type = res.headers.get("Content-Type", "").lower()
                    if "html" in content_type and "WordPress" not in res.text and "wp-admin" not in res.text:
                        return None
                    return (name, sev, f"Accessible at /{path}. {desc}")
            except Exception:
                return None
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for result in ex.map(check_path, checks):
                if result:
                    name, sev, desc = result
                    self.add_vuln(name, sev, desc)
                    self.log(f"Finding: {name} detected", "warning")

        self.check_directory_listings()

    def _is_directory_listing(self, body):
        if not body:
            return False
        markers = ("Index of", "Parent Directory", "Directory listing for")
        if any(marker in body for marker in markers):
            return True
        return "Last modified" in body and re.search(r'<a\s+[^>]*href=["\'][^"\']+["\']', body, re.I)

    def _parse_directory_listing(self, html):
        entries = []
        seen = set()
        for href in re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\']', html, re.I):
            href = href.strip()
            if not href or href in (".", "./", "../", "/"):
                continue
            if href.startswith(("?", "#")) or "://" in href:
                continue
            is_dir = href.endswith("/")
            name = href.rstrip("/").split("/")[-1]
            if not name or name == "..":
                continue
            key = (name.lower(), is_dir)
            if key in seen:
                continue
            seen.add(key)
            entries.append((name, href, is_dir))
        return entries

    def _join_listing_path(self, base_path, href):
        return urljoin(base_path, href).lstrip("/")

    def _is_sensitive_dir(self, name):
        lowered = (name or "").lower()
        return any(keyword in lowered for keyword in SENSITIVE_DIR_KEYWORDS)

    def _classify_sensitive_file(self, name, full_path=None):
        if self._is_image_file(name):
            return None

        for pattern, severity, reason in SENSITIVE_FILE_RULES:
            if pattern.search(name or ""):
                return severity, reason

        lowered = (name or "").lower()
        if SUSPICIOUS_PHP_PATTERN.search(lowered):
            return "Critical", "Suspicious PHP script exposed in directory listing"

        if lowered.endswith(".php") and full_path and self._is_under_uploads(full_path):
            return "High", "PHP script exposed in uploads directory"

        return None

    def _verify_exposed_file(self, full_path, name):
        """HTTP test to confirm a listed file is actually accessible, not a dead listing entry."""
        if self._is_image_file(name):
            return False, "Image file ignored"

        try:
            res = self.get(full_path, timeout=5)
        except Exception:
            return False, "Request failed"

        if res.status_code != 200:
            return False, f"HTTP {res.status_code}"

        content = res.content or b""
        content_len = len(content)
        if content_len < 10:
            return False, "Empty response"

        content_type = (res.headers.get("Content-Type") or "").lower()
        if content_type.startswith("image/"):
            return False, "Served as image"

        text_sample = ""
        try:
            text_sample = res.text[:4000]
        except Exception:
            text_sample = ""

        text_lower = text_sample.lower()
        ext = self._file_extension(name)

        if "html" in content_type or text_sample.lstrip().startswith("<"):
            error_markers = (
                "404 not found",
                "page not found",
                "not found",
                "403 forbidden",
                "access denied",
                "forbidden",
            )
            if any(marker in text_lower for marker in error_markers):
                if "<?php" not in text_sample and "DB_" not in text_sample:
                    return False, "HTML error page"

        if ext == ".php":
            if "<?php" in text_sample or "DB_PASSWORD" in text_sample or "DB_NAME" in text_sample:
                return True, "PHP source/config leak confirmed via HTTP"
            if 'name="log"' in text_lower and "wp-login" in text_lower:
                return False, "Login page, not raw PHP exposure"
            if content_len > 50:
                return True, "PHP file accessible and returns content"
            return False, "PHP response too small"

        if ext in (".sql", ".db", ".sqlite") or ".sql" in name.lower():
            if any(token in text_sample for token in ("INSERT INTO", "CREATE TABLE", "DROP TABLE", "mysqldump")):
                return True, "Database dump content confirmed"
            return content_len > 100, "File accessible"

        if ext in (".zip", ".gz", ".tar", ".rar", ".7z", ".tgz"):
            magic = content[:4]
            if magic[:2] == b"PK" or magic[:2] == b"\x1f\x8b" or content[:4] == b"Rar!":
                return True, "Archive content confirmed"
            return False, "Invalid archive signature"

        lowered_name = (name or "").lower()
        if "wp-config" in lowered_name or ".env" in lowered_name or "password" in lowered_name:
            if any(token in text_sample for token in ("DB_", "PASSWORD", "SECRET", "API_KEY", "define(")):
                return True, "Secrets/config confirmed in response"
            return content_len > 30, "Sensitive file accessible"

        if content_len > 30:
            return True, "File confirmed accessible via HTTP"
        return False, "Insufficient content"

    def _probe_directory_listing(self, path):
        try:
            res = self.get(path, timeout=5)
            if res.status_code == 200 and self._is_directory_listing(res.text):
                return path
        except Exception:
            return None
        return None

    def _is_under_uploads(self, path):
        normalized = (path or "").lower().replace("\\", "/").strip("/")
        return normalized.startswith("uploads/") or "/uploads/" in f"/{normalized}/" or normalized == "uploads"

    def _listing_max_depth(self, root_path):
        return UPLOAD_LISTING_MAX_DEPTH if self._is_under_uploads(root_path) else DEFAULT_LISTING_MAX_DEPTH

    def _should_descend_into_dir(self, dir_name, full_path, depth, max_depth):
        if depth >= max_depth:
            return False
        if self._is_under_uploads(full_path) or (dir_name or "").lower() == "uploads":
            return True
        return self._is_sensitive_dir(dir_name)

    def _explore_listed_directory(self, root_path, max_depth=None, max_entries=150):
        max_depth = max_depth if max_depth is not None else self._listing_max_depth(root_path)
        under_uploads = self._is_under_uploads(root_path)
        if under_uploads:
            max_entries = 250

        visited = set()
        reported_files = set()
        reported_dirs = set()
        queue = [(root_path.rstrip("/") + "/", 0)]

        while queue:
            path, depth = queue.pop(0)
            norm_path = path.rstrip("/") + "/"
            if norm_path in visited or depth > max_depth:
                continue
            visited.add(norm_path)

            try:
                res = self.get(norm_path, timeout=5)
                if res.status_code != 200 or not self._is_directory_listing(res.text):
                    continue
            except Exception:
                continue

            entries = self._parse_directory_listing(res.text)[:max_entries]
            subdirs = []
            files = []

            for name, href, is_dir in entries:
                if is_dir:
                    subdirs.append((name, href))
                else:
                    files.append((name, href))

            subdirs.sort(key=lambda item: (not self._is_sensitive_dir(item[0]), item[0].lower()))

            for name, href in subdirs:
                full_path = self._join_listing_path(norm_path, href)

                if self._is_sensitive_dir(name) and full_path not in reported_dirs:
                    reported_dirs.add(full_path)
                    severity = "High" if self._is_under_uploads(full_path) else "Medium"
                    self.add_vuln(
                        f"Exposed Sensitive Directory: {name}",
                        severity,
                        f"Sensitive directory browsable via open listing at /{full_path}.",
                    )
                    self.log(f"Sensitive directory exposed via listing: /{full_path}", "warning")

                if self._should_descend_into_dir(name, full_path, depth, max_depth):
                    label = "uploads subdirectory" if self._is_under_uploads(full_path) else "directory"
                    self.log(f"Scanning {label} /{full_path}", "info")
                    queue.append((full_path, depth + 1))

            for name, href in files:
                full_path = self._join_listing_path(norm_path, href)
                if self._is_image_file(name):
                    continue

                classified = self._classify_sensitive_file(name, full_path)
                if not classified or full_path in reported_files:
                    continue

                verified, verify_detail = self._verify_exposed_file(full_path, name)
                if not verified:
                    self.log(f"Skipped listing entry (not accessible): /{full_path} — {verify_detail}", "info")
                    continue

                severity, reason = classified
                reported_files.add(full_path)
                self.add_vuln(
                    f"Exposed Sensitive File: {name}",
                    severity,
                    f"Verified via HTTP at /{full_path}. {reason}. ({verify_detail})",
                )
                self.log(f"Sensitive file verified via HTTP: /{full_path}", "warning")

    def check_directory_listings(self):
        self.log("Checking open directories for sensitive files...")

        open_dirs = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for path in ex.map(self._probe_directory_listing, LISTING_ROOT_DIRS):
                if path:
                    open_dirs.append(path)

        for path in open_dirs:
            self.add_vuln(
                "Directory Listing",
                "Medium",
                f"Directory listing enabled on /{path}. Contents are browsable by anyone.",
            )
            self.log(f"Directory listing active on /{path}", "warning")
            self._explore_listed_directory(path)

    def _has_plugin(self, slug):
        return any(p["slug"] == slug for p in self.results["plugins"])

    def _has_theme(self, slug):
        return any(t["slug"] == slug for t in self.results["themes"])

    @staticmethod
    def _is_valid_component_slug(slug):
        slug = (slug or "").strip().lower()
        if len(slug) < MIN_COMPONENT_SLUG_LEN:
            return False
        return bool(COMPONENT_SLUG_PATTERN.match(slug))

    @staticmethod
    def _version_is_unknown(version):
        return (version or "Unknown").strip().lower() in ("unknown", "none", "")

    @staticmethod
    def _is_html_error_page(text):
        head = (text or "")[:500].lower()
        return "<html" in head or "<!doctype html" in head

    @staticmethod
    def _looks_like_plugin_readme(text):
        if not text or WordPressScanner._is_html_error_page(text):
            return False
        return bool(
            re.search(r"(?im)^\s*Stable tag:\s*", text)
            or re.search(r"(?im)^\s*=== .+ ===\s*$", text)
        )

    @staticmethod
    def _looks_like_theme_style(text):
        if not text or WordPressScanner._is_html_error_page(text):
            return False
        return bool(re.search(r"(?im)^\s*Theme Name:\s*", text[:8000]))

    @staticmethod
    def _looks_like_plugin_header(text):
        if not text or WordPressScanner._is_html_error_page(text):
            return False
        head = text[:8000]
        return bool(re.search(r"(?im)^\s*Plugin Name:\s*", head))

    @staticmethod
    def _extract_version_from_asset_url(slug, url):
        if slug.lower() not in (url or "").lower():
            return None
        match = ASSET_VERSION_PARAM.search(url)
        if not match:
            return None
        version = match.group(1).strip()
        if not version or version.lower() in ("null", "undefined"):
            return None
        return version

    def _extract_components_from_html(self, html):
        """Extract plugin/theme slugs and versions from HTML and enqueued CSS/JS URLs."""
        text = html or ""
        plugins = {}
        themes = {}
        asset_urls = []

        for slug in set(re.findall(r"wp-content/plugins/([^/\s?\"']+)", text, re.I)):
            slug = slug.lower()
            if not self._is_valid_component_slug(slug):
                continue
            plugins[slug] = "Unknown"

        for slug in set(re.findall(r"wp-content/themes/([^/\s?\"']+)", text, re.I)):
            slug = slug.lower()
            if not self._is_valid_component_slug(slug):
                continue
            themes[slug] = "Unknown"

        for match in re.finditer(
            r"<(?:link|script)\b[^>]*\b(?:href|src)\s*=\s*[\"']([^\"']+)[\"']",
            text,
            re.I,
        ):
            url = match.group(1)
            if "wp-content/plugins/" not in url and "wp-content/themes/" not in url:
                continue
            asset_urls.append(url)
            for slug in re.findall(r"wp-content/plugins/([^/\s?\"']+)", url, re.I):
                slug = slug.lower()
                if not self._is_valid_component_slug(slug):
                    continue
                if slug not in plugins or self._version_is_unknown(plugins.get(slug)):
                    ver = self._extract_version_from_asset_url(slug, url)
                    if ver:
                        plugins[slug] = ver
                    elif slug not in plugins:
                        plugins[slug] = "Unknown"
            for slug in re.findall(r"wp-content/themes/([^/\s?\"']+)", url, re.I):
                slug = slug.lower()
                if not self._is_valid_component_slug(slug):
                    continue
                if slug not in themes or self._version_is_unknown(themes.get(slug)):
                    ver = self._extract_version_from_asset_url(slug, url)
                    if ver:
                        themes[slug] = ver
                    elif slug not in themes:
                        themes[slug] = "Unknown"

        return plugins, themes, asset_urls

    def _register_component(self, kind, slug, version="Unknown", source="homepage", page_url=None):
        slug = (slug or "").strip().lower()
        if not self._is_valid_component_slug(slug):
            return False

        is_plugin = kind == "plugin"
        bucket = self.results["plugins"] if is_plugin else self.results["themes"]
        has_fn = self._has_plugin if is_plugin else self._has_theme

        if has_fn(slug):
            for item in bucket:
                if item["slug"] == slug:
                    if self._version_is_unknown(item.get("version")) and not self._version_is_unknown(version):
                        item["version"] = version
                    if page_url:
                        found_on = item.setdefault("found_on", [])
                        if page_url not in found_on:
                            found_on.append(page_url)
                    break
            return False

        entry = {"slug": slug, "version": version or "Unknown", "source": source}
        if page_url:
            entry["found_on"] = [page_url]
        bucket.append(entry)
        return True

    def _apply_extracted_components(self, html, source="homepage", page_url=None):
        plugins, themes, _ = self._extract_components_from_html(html)
        new_plugins = 0
        new_themes = 0
        for slug, version in plugins.items():
            if self._register_component("plugin", slug, version, source=source, page_url=page_url):
                new_plugins += 1
        for slug, version in themes.items():
            if self._register_component("theme", slug, version, source=source, page_url=page_url):
                new_themes += 1
        return new_plugins, new_themes

    def _is_asset_crawl_candidate(self, url):
        full = urljoin(self.target_url + "/", (url or "").strip())
        if not self._same_origin(full):
            return False
        parsed = urlparse(full)
        path = parsed.path or "/"
        if path in ("", "/"):
            return False
        if ASSET_CRAWL_SKIP_PATTERN.search(path):
            return False
        return True

    def _classify_crawl_page(self, url):
        path = urlparse(url).path or ""
        if SHOP_PATH_PATTERN.search(path):
            return "woocommerce"
        if POST_PATH_PATTERN.search(path):
            return "post"
        if re.search(r"/product/", path, re.I):
            return "product"
        return "page"

    def _discover_asset_crawl_targets(self, homepage):
        targets = []
        seen = set()

        def add(url, page_type, source):
            full = urljoin(self.target_url + "/", (url or "").strip())
            if not self._is_asset_crawl_candidate(full):
                return
            normalized = full.rstrip("/")
            if normalized in seen:
                return
            seen.add(normalized)
            targets.append({"url": full, "type": page_type, "source": source})

        sitemap_urls = self.results.get("site_intelligence", {}).get("sitemap", {}).get("urls") or []
        shop_urls = []
        post_urls = []
        page_urls = []

        for url in sitemap_urls:
            page_type = self._classify_crawl_page(url)
            if page_type == "woocommerce":
                shop_urls.append(url)
            elif page_type in ("post", "product"):
                post_urls.append(url)
            elif page_type == "page":
                page_urls.append(url)

        for url in shop_urls[:MAX_ASSET_CRAWL_SHOP]:
            add(url, "woocommerce", "sitemap")
        for url in post_urls[:MAX_ASSET_CRAWL_POSTS]:
            add(url, "post", "sitemap")
        for url in page_urls[:MAX_ASSET_CRAWL_INTERNAL]:
            add(url, "page", "sitemap")

        for path in WOOCOMMERCE_PROBE_PATHS:
            add(path, "woocommerce", "probe")

        rest_endpoints = (
            ("wp-json/wp/v2/posts", "post", MAX_ASSET_CRAWL_POSTS),
            ("wp-json/wp/v2/pages", "page", MAX_ASSET_CRAWL_INTERNAL),
            ("wp-json/wp/v2/product", "product", MAX_ASSET_CRAWL_SHOP),
        )
        for endpoint, page_type, limit in rest_endpoints:
            try:
                res = self.get(endpoint, params={"per_page": limit, "_fields": "link"}, timeout=5)
                if res.status_code != 200:
                    continue
                content_type = res.headers.get("Content-Type", "")
                if not content_type.startswith("application/json"):
                    continue
                for item in res.json():
                    link = (item.get("link") or "").strip()
                    if link:
                        add(link, page_type, "rest_api")
            except Exception:
                continue

        for match in re.finditer(r"<a\b([^>]*)>(.*?)</a>", homepage or "", re.I | re.S):
            attrs = self._parse_tag_attrs(match.group(1))
            href = (attrs.get("href") or "").strip()
            if not href or href.startswith("#") or href.lower().startswith("javascript:"):
                continue
            full = urljoin(self.target_url + "/", href)
            if not self._is_asset_crawl_candidate(full):
                continue
            page_type = self._classify_crawl_page(full)
            if page_type in ("woocommerce", "post", "product"):
                add(href, page_type, "homepage_link")

        type_priority = {"woocommerce": 0, "product": 1, "post": 2, "page": 3}
        targets.sort(key=lambda t: (type_priority.get(t["type"], 9), t["url"]))
        return targets[:MAX_ASSET_CRAWL_PAGES]

    def _fetch_page_html(self, url):
        parsed = urlparse(url)
        if not self._same_origin(url):
            return None
        path = (parsed.path or "/").lstrip("/")
        if parsed.query:
            path = f"{path}?{parsed.query}"
        try:
            res = self.get(path, timeout=self.timeout)
            if res.status_code == 200 and res.text:
                return res.text
        except Exception:
            return None
        return None

    def _crawl_internal_pages_for_assets(self, homepage):
        targets = self._discover_asset_crawl_targets(homepage)
        if not targets:
            self.log("No internal pages selected for deep asset crawl.", "info")
            return

        self.log(
            f"Deep-crawling {len(targets)} internal page(s) for CSS/JS plugin footprints "
            f"(posts, shop, WooCommerce)...",
            "info",
        )

        crawl_meta = self.results["asset_crawl"]
        total_new_plugins = 0
        total_new_themes = 0

        def crawl_one(target):
            html = self._fetch_page_html(target["url"])
            if not html:
                return None
            new_plugins, new_themes = self._apply_extracted_components(
                html,
                source="asset_crawl",
                page_url=target["url"],
            )
            _, _, asset_urls = self._extract_components_from_html(html)
            plugin_assets = [u for u in asset_urls if "wp-content/plugins/" in u]
            return {
                "url": target["url"],
                "type": target["type"],
                "source": target["source"],
                "new_plugins": new_plugins,
                "new_themes": new_themes,
                "plugin_assets": len(plugin_assets),
            }

        workers = min(self.max_workers, 8, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for result in ex.map(crawl_one, targets):
                if not result:
                    continue
                crawl_meta["pages_crawled"].append(result)
                total_new_plugins += result["new_plugins"]
                total_new_themes += result["new_themes"]
                if result["new_plugins"] or result["new_themes"]:
                    self.log(
                        f"Asset crawl [{result['type']}]: {result['new_plugins']} plugin(s), "
                        f"{result['new_themes']} theme(s) from {urlparse(result['url']).path or '/'}",
                        "success",
                    )
                elif result["plugin_assets"]:
                    self.log(
                        f"Asset crawl [{result['type']}]: scanned {result['plugin_assets']} plugin asset(s) "
                        f"on {urlparse(result['url']).path or '/'} (no new components)",
                        "info",
                    )

        crawl_meta["plugins_discovered"] = total_new_plugins
        crawl_meta["themes_discovered"] = total_new_themes

        if total_new_plugins or total_new_themes:
            self.log(
                f"Deep asset crawl found {total_new_plugins} additional plugin(s) and "
                f"{total_new_themes} theme(s) not present on homepage.",
                "success",
            )
        else:
            self.log("Deep asset crawl completed — no new plugins/themes beyond homepage.", "info")

    def detect_plugins_and_themes(self, text):
        # 1. Passive parsing of the homepage
        self.log("Parsing HTML for plugin and theme footprints...")
        self._apply_extracted_components(text, source="homepage")
        self.emit_progress(
            "components_passive",
            plugins=list(self.results["plugins"]),
            themes=list(self.results["themes"]),
        )

        # 2. Deep crawl internal pages (posts, shop, WooCommerce) for enqueued CSS/JS
        self._crawl_internal_pages_for_assets(text)
        self.emit_progress(
            "components_crawl",
            plugins=list(self.results["plugins"]),
            themes=list(self.results["themes"]),
            asset_crawl=self.results["asset_crawl"],
        )

        # 3. Active probing via cached wordpress.org catalog (500 popular each)
        plugin_slugs = get_popular_plugins()
        theme_slugs = get_popular_themes()
        self.log(f"Probing {len(plugin_slugs)} popular plugins (cached catalog)...")
        self._probe_popular("plugins", plugin_slugs)
        self.emit_progress(
            "components_probe",
            plugins=list(self.results["plugins"]),
            themes=list(self.results["themes"]),
        )
        self.log(f"Probing {len(theme_slugs)} popular themes (cached catalog)...")
        self._probe_popular("themes", theme_slugs)
        self.emit_progress(
            "components_probe",
            plugins=list(self.results["plugins"]),
            themes=list(self.results["themes"]),
        )

        self._resolve_component_versions()
        self.emit_progress(
            "components_resolved",
            plugins=list(self.results["plugins"]),
            themes=list(self.results["themes"]),
        )

        self.log(
            f"Identified {len(self.results['plugins'])} plugins and "
            f"{len(self.results['themes'])} themes.",
            "info",
        )

    @staticmethod
    def _parse_plugin_readme_version(text):
        if not text:
            return None
        match = PLUGIN_README_VERSION.search(text)
        if match:
            return match.group(1)
        fallback = PLUGIN_README_VERSION_FALLBACK.search(text)
        return fallback.group(1) if fallback else None

    @staticmethod
    def _parse_theme_style_version(text):
        if not text:
            return None
        head = text[:8000]
        match = THEME_STYLE_VERSION.search(head)
        if match:
            return match.group(1)
        fallback = THEME_STYLE_VERSION_FALLBACK.search(head)
        return fallback.group(1) if fallback else None

    def _fetch_plugin_version(self, slug):
        try:
            res = self.get(f"wp-content/plugins/{slug}/readme.txt", timeout=4)
            if res.status_code == 200 and res.text.strip():
                if self._looks_like_plugin_readme(res.text):
                    version = self._parse_plugin_readme_version(res.text)
                    if version:
                        return version, "readme.txt"
        except Exception:
            pass

        try:
            res = self.get(f"wp-content/plugins/{slug}/{slug}.php", timeout=4)
            if res.status_code == 200 and res.text.strip():
                if self._looks_like_plugin_header(res.text):
                    head = res.text[:8000]
                    match = PLUGIN_HEADER_VERSION.search(head) or PLUGIN_HEADER_VERSION_FALLBACK.search(head)
                    if match:
                        return match.group(1), "plugin_header"
        except Exception:
            pass
        return None, None

    def _fetch_theme_version(self, slug):
        try:
            res = self.get(f"wp-content/themes/{slug}/style.css", timeout=4)
            if res.status_code == 200 and res.text.strip():
                if self._looks_like_theme_style(res.text):
                    version = self._parse_theme_style_version(res.text)
                    if version:
                        return version, "style.css"
        except Exception:
            pass
        return None, None

    def _resolve_component_versions(self):
        plugins = [
            p for p in self.results["plugins"] if self._version_is_unknown(p.get("version"))
        ]
        themes = [
            t for t in self.results["themes"] if self._version_is_unknown(t.get("version"))
        ]
        if not plugins and not themes:
            return

        self.log(
            f"Resolving versions from readme.txt/style.css for "
            f"{len(plugins)} plugin(s) and {len(themes)} theme(s)...",
            "info",
        )

        resolved_plugins = 0
        resolved_themes = 0

        def resolve_plugin(item):
            version, source = self._fetch_plugin_version(item["slug"])
            return item["slug"], version, source

        def resolve_theme(item):
            version, source = self._fetch_theme_version(item["slug"])
            return item["slug"], version, source

        workers = min(self.max_workers, 12, max(len(plugins) + len(themes), 1))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            plugin_futures = [ex.submit(resolve_plugin, p) for p in plugins]
            theme_futures = [ex.submit(resolve_theme, t) for t in themes]

            for fut in as_completed(plugin_futures):
                slug, version, source = fut.result()
                if not version:
                    continue
                for item in self.results["plugins"]:
                    if item["slug"] == slug:
                        item["version"] = version
                        item["version_source"] = source or "readme.txt"
                        resolved_plugins += 1
                        self.log(f"Resolved plugin version: {slug} v{version}", "success")
                        break

            for fut in as_completed(theme_futures):
                slug, version, source = fut.result()
                if not version:
                    continue
                for item in self.results["themes"]:
                    if item["slug"] == slug:
                        item["version"] = version
                        item["version_source"] = source or "style.css"
                        resolved_themes += 1
                        self.log(f"Resolved theme version: {slug} v{version}", "success")
                        break

        if resolved_plugins or resolved_themes:
            self.log(
                f"Version resolution complete — {resolved_plugins} plugin(s), "
                f"{resolved_themes} theme(s) resolved.",
                "success",
            )
        else:
            self.log(
                "Could not resolve component versions from readme.txt/style.css "
                "(files blocked or not exposed).",
                "info",
            )

    def _probe_popular(self, kind, slugs):
        is_plugin = kind == "plugins"
        existing = self._has_plugin if is_plugin else self._has_theme
        bucket = self.results[kind]
        probe_file = "readme.txt" if is_plugin else "style.css"

        def probe(slug):
            if existing(slug):
                return None
            try:
                res = self.get(f"wp-content/{kind}/{slug}/{probe_file}", timeout=4)
                if res.status_code != 200 or not res.text.strip():
                    return None
                if is_plugin:
                    if not self._looks_like_plugin_readme(res.text):
                        return None
                    parsed = self._parse_plugin_readme_version(res.text)
                else:
                    if not self._looks_like_theme_style(res.text):
                        return None
                    parsed = self._parse_theme_style_version(res.text)
                return {"slug": slug, "version": parsed or "Unknown"}
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(probe, s): s for s in slugs}
            for fut in as_completed(futures):
                found = fut.result()
                if not found:
                    continue
                with self._component_lock:
                    if existing(found["slug"]):
                        continue
                    found["source"] = "active_probe"
                    bucket.append(found)
                label = "plugin" if is_plugin else "theme"
                self.log(f"Detected {label}: {found['slug']} (v{found['version']})", "success")

    def lookup_vulnerabilities(self):
        vuln_cfg = self.scan_config.get("vuln_lookup", {})
        if not vuln_cfg.get("enabled", True):
            self.log("Version vulnerability lookup disabled in settings.", "info")
            self._lookup_vulnerabilities_legacy()
            return

        api_token = (vuln_cfg.get("wpscan_api_token") or "").strip()

        def log_msg(message, type="info"):
            self.log(message, type)

        enrichment = enrich_scan_components(
            self.results["plugins"],
            self.results["themes"],
            self.results["version"],
            api_token=api_token,
            log_callback=log_msg,
        )

        self.results["plugins"] = enrichment["plugins"]
        self.results["themes"] = enrichment["themes"]
        self.results["core_version_status"] = enrichment.get("core_status")
        self.results["component_vulnerabilities"] = enrichment.get("known_vulnerabilities") or []

        for vuln in self.results["component_vulnerabilities"]:
            slug = vuln.get("component_slug", "?")
            kind = vuln.get("component_type", "component")
            installed = vuln.get("installed_version", "?")
            self.add_vuln(
                f"Known CVE: {slug} ({kind})",
                vuln.get("severity", "High"),
                (
                    f"Installed version {installed} is affected by: {vuln.get('title')}. "
                    f"{('Fixed in ' + vuln['fixed_in'] + '. ') if vuln.get('fixed_in') else ''}"
                    f"{vuln.get('description', '')[:300]}"
                ).strip(),
                cve_id=vuln.get("id"),
                component=slug,
                source=vuln.get("source") or "wpscan",
                finding_type="cve",
            )

        core = enrichment.get("core_status")
        if core and core.get("outdated"):
            self.add_update(
                f"Update WordPress Core ({core.get('installed_version')})",
                (
                    f"Installed WordPress {core.get('installed_version')} is behind the latest "
                    f"{core.get('latest_version')}. Update recommended."
                ),
                kind="core",
            )

        for p in self.results["plugins"]:
            if p.get("outdated") and not p.get("vulnerable"):
                self.add_update(
                    f"Update available: {p['slug']}",
                    (
                        f"Version {p.get('version')} is behind the latest {p.get('latest_version')} "
                        f"on wordpress.org. Update recommended."
                    ),
                    component=p["slug"],
                    kind="plugin",
                )

        for t in self.results["themes"]:
            if t.get("outdated") and not t.get("vulnerable"):
                self.add_update(
                    f"Update available: {t['slug']}",
                    (
                        f"Version {t.get('version')} is behind the latest {t.get('latest_version')} "
                        f"on wordpress.org. Update recommended."
                    ),
                    component=t["slug"],
                    kind="theme",
                )

        if enrichment.get("wpscan_rate_limited"):
            self.log("WPScan API daily limit reached — remaining components skipped.", "warning")

    def run_dynamic_analysis(self):
        dyn_cfg = self.scan_config.get("dynamic_analysis", {})
        inj_cfg = self.scan_config.get("injection", {})
        vuln_cfg = self.scan_config.get("vuln_lookup", {})

        if not dyn_cfg.get("enabled", True):
            self.log("Dynamic PoC verification disabled in settings.", "info")
            return

        if not vuln_cfg.get("enabled", True) and not inj_cfg.get("enabled", True):
            self.log(
                "Dynamic analysis skipped — enable vulnerability lookup or injection testing in settings.",
                "info",
            )
            return

        known = self.results.get("component_vulnerabilities") or []
        if not known:
            self.log("No version-specific CVEs to verify dynamically.", "info")
            return

        def log_msg(message, type="info"):
            self.log(message, type)

        findings = run_dynamic_verification(
            self._get_session(),
            self.target_url,
            known,
            config=dyn_cfg,
            log_callback=log_msg,
            timeout=self.timeout,
        )
        self.results["dynamic_analysis_findings"] = findings

        for item in findings:
            if not item.get("verified"):
                continue
            slug = item.get("component_slug", "?")
            kind = item.get("component_type", "plugin")
            category = (item.get("category") or "vuln").upper()
            path_hint = f" at /{item['path']}" if item.get("path") else ""
            self.add_vuln(
                f"CONFIRMED [{category}]: {slug} ({kind})",
                item.get("severity", "Critical"),
                (
                    f"Passive CVE lookup matched '{item.get('vuln_title')}', and a safe PoC probe "
                    f"detected a live vulnerability signature{path_hint}. "
                    f"{item.get('detail', '')}. "
                    f"{item.get('safe_note', '')}"
                ).strip(),
                cve_id=item.get("vuln_id"),
                component=slug,
                source="dynamic_analysis",
                verified_dynamic=True,
                poc_template=item.get("template_id"),
                probe_type=item.get("probe_type"),
            )

            for comp_list, comp_kind in (
                (self.results["plugins"], "plugin"),
                (self.results["themes"], "theme"),
            ):
                for comp in comp_list:
                    if comp.get("slug") == slug:
                        comp.setdefault("dynamic_verified", []).append(
                            {
                                "vuln_id": item.get("vuln_id"),
                                "template_id": item.get("template_id"),
                                "detail": item.get("detail"),
                            }
                        )

    def _lookup_vulnerabilities_legacy(self):
        """Fallback when online CVE lookup is disabled — core version only."""
        self.log("Running basic version checks (CVE lookup disabled)...")
        core = self.results.get("core_version_status")
        if core and core.get("outdated"):
            self.add_update(
                f"Update WordPress Core ({core.get('installed_version')})",
                (
                    f"Installed WordPress {core.get('installed_version')} is behind the latest "
                    f"{core.get('latest_version')}. Update recommended."
                ),
                kind="core",
            )
            return

        wp_ver = parse_version(self.results["version"])
        if not wp_ver:
            return
        display = self.results["version"]
        if wp_ver < (6, 0):
            self.add_update(
                f"Update WordPress Core ({display})",
                "This WordPress version is significantly outdated. Update recommended.",
                kind="core",
            )

    def add_update(self, name, description, **extra):
        for existing in self.results["update_recommendations"]:
            if existing.get("name") == name:
                return
        item = {"name": name, "description": description, "finding_type": "update"}
        item.update(extra)
        self.results["update_recommendations"].append(item)

    def add_vuln(self, name, severity, description, **extra):
        component = extra.get("component")
        for existing in self.results["vulnerabilities"]:
            if existing.get("name") == name and existing.get("component") == component:
                return
        vuln = {"name": name, "severity": severity, "description": description, "finding_type": "security"}
        vuln.update(extra)
        self.results["vulnerabilities"].append(vuln)

    def _finalize(self):
        counts = {k: 0 for k in SEVERITY_ORDER}
        for v in self.results["vulnerabilities"]:
            counts[v["severity"]] = counts.get(v["severity"], 0) + 1
        self.results["severity_counts"] = counts
        self.results["vulnerabilities"].sort(
            key=lambda v: SEVERITY_ORDER.get(v["severity"], 0), reverse=True
        )
