import eventlet

eventlet.monkey_patch()

import json
import os
import time
from io import BytesIO
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request, send_file
from sqlalchemy import text
from flask_cors import CORS
from flask_socketio import SocketIO, emit


class _UnicodeJsonModule:
    @staticmethod
    def dumps(*args, **kwargs):
        kwargs.setdefault("ensure_ascii", False)
        return json.dumps(*args, **kwargs)

    @staticmethod
    def loads(*args, **kwargs):
        return json.loads(*args, **kwargs)

from ai_analyzer import (
    AIAnalyzerError,
    analyze_scan_results,
    fetch_available_models,
    finalize_analysis_result,
    is_thinking_model,
    merge_ai_config,
    test_ai_connection,
)
from models import ScanResult, db
from pdf_report import generate_pdf
from scanner import WordPressScanner
from settings_manager import (
    DEFAULT_SETTINGS,
    DEFAULT_SYSTEM_PROMPT,
    PROVIDER_PRESETS,
    _load_stored_settings,
    get_proxy_dict,
    get_settings,
    get_wordfence_api_key,
    save_settings,
    settings_for_client,
)
from runtime_paths import data_root, database_dir, resource_root
from wordfence_cache import WordfenceCacheError, ensure_wordfence_ready, get_cache_status, refresh_wordfence_cache
from wp_catalog_cache import ensure_catalog_ready

# Absolute path for the database to avoid "unable to open database file" errors.
basedir = data_root()


def _load_env_file():
    env_path = os.path.join(basedir, ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key and key not in os.environ:
                os.environ[key] = value


_load_env_file()
db_dir = database_dir()

app = Flask(
    __name__,
    template_folder=os.path.join(resource_root(), "templates"),
    static_folder=os.path.join(resource_root(), "static"),
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(db_dir, "scans.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("WP_SCANNER_SECRET", os.urandom(24).hex())
app.config["JSON_ASCII"] = False

CORS(app)
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet", json=_UnicodeJsonModule)

with app.app_context():
    db.create_all()
    with db.engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.commit()
    ensure_wordfence_ready(get_wordfence_api_key, background=True)

ensure_catalog_ready(background=True)

_last_scan_by_sid = {}
_analysis_results_by_sid = {}


def _remember_scan(sid, results):
    if sid and results:
        _last_scan_by_sid[sid] = results


def _resolve_scan_data(sid, scan_data=None):
    if scan_data:
        return scan_data
    return _last_scan_by_sid.get(sid)


def _validate_ai_request(ai_override=None):
    with app.app_context():
        cfg = merge_ai_config(get_settings().get("ai", {}), ai_override)
    if not cfg.get("enabled"):
        raise AIAnalyzerError("AI analysis is disabled.")
    if not (cfg.get("model") or "").strip():
        raise AIAnalyzerError("AI model is not configured.")
    provider = (cfg.get("provider") or "custom").lower()
    api_key = (cfg.get("api_key") or "").strip()
    if provider != "ollama" and not api_key:
        raise AIAnalyzerError("API key is required for this provider.")
    return cfg


def normalize_url(raw):
    """Validate and normalize a user-supplied target URL. Returns None if invalid."""
    raw = (raw or "").strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc or "." not in parsed.netloc:
        return None
    return raw


@app.route("/")
def index():
    return render_template("index.html")


@app.after_request
def add_charset(response):
    content_type = response.content_type or ""
    if content_type.startswith("text/") and "charset=" not in content_type.lower():
        response.headers["Content-Type"] = f"{content_type}; charset=utf-8"
    return response


@app.route("/api/history", methods=["GET"])
def get_history():
    scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    return jsonify([s.to_dict() for s in scans])


@app.route("/api/settings", methods=["GET"])
def api_get_settings():
    return jsonify(settings_for_client())


@app.route("/api/settings", methods=["PUT"])
def api_save_settings():
    data = request.get_json(silent=True) or {}
    current = _load_stored_settings()

    if "proxy" in data:
        proxy = data["proxy"]
        current["proxy"]["enabled"] = bool(proxy.get("enabled", current["proxy"]["enabled"]))
        if "url" in proxy:
            current["proxy"]["url"] = (proxy.get("url") or "").strip()

    if "ai" in data:
        ai = data["ai"]
        for key in ("enabled", "auto_analyze"):
            if key in ai:
                current["ai"][key] = bool(ai[key])
        for key in ("provider", "base_url", "model", "system_prompt"):
            if key in ai:
                current["ai"][key] = ai[key]
        if ai.get("api_key"):
            current["ai"]["api_key"] = ai["api_key"]

    if "scan" in data:
        scan = data["scan"]
        inj = scan.get("injection") or {}
        inj_cfg = current.setdefault("scan", {}).setdefault("injection", {})
        for key in ("enabled", "test_sql", "test_xss"):
            if key in inj:
                inj_cfg[key] = bool(inj[key])
        if "max_forms" in inj:
            inj_cfg["max_forms"] = max(1, min(int(inj["max_forms"] or 1), 30))

        dyn = scan.get("dynamic_analysis") or {}
        dyn_cfg = current.setdefault("scan", {}).setdefault("dynamic_analysis", {})
        for key in ("enabled", "test_rce", "test_sqli"):
            if key in dyn:
                dyn_cfg[key] = bool(dyn[key])
        if "max_probes" in dyn:
            dyn_cfg["max_probes"] = max(1, min(int(dyn["max_probes"] or 1), 50))
        if "delay_seconds" in dyn:
            dyn_cfg["delay_seconds"] = max(0.0, min(float(dyn["delay_seconds"] or 0), 5.0))
        if dyn.get("min_severity") in ("Critical", "High"):
            dyn_cfg["min_severity"] = dyn["min_severity"]

        vuln = scan.get("vuln_lookup") or {}
        vuln_cfg = current.setdefault("scan", {}).setdefault("vuln_lookup", {})
        if "enabled" in vuln:
            vuln_cfg["enabled"] = bool(vuln["enabled"])
        if vuln.get("wpscan_api_token"):
            vuln_cfg["wpscan_api_token"] = vuln["wpscan_api_token"]
        if vuln.get("wordfence_api_key"):
            vuln_cfg["wordfence_api_key"] = vuln["wordfence_api_key"]

    save_settings(current)
    return jsonify(settings_for_client())


@app.route("/api/settings/defaults", methods=["GET"])
def api_settings_defaults():
    return jsonify(
        {
            "system_prompt": DEFAULT_SYSTEM_PROMPT,
            "presets": PROVIDER_PRESETS,
            "defaults": DEFAULT_SETTINGS,
        }
    )


@app.route("/api/wordfence/status", methods=["GET"])
def api_wordfence_status():
    return jsonify(get_cache_status())


_wordfence_update_running = False


@app.route("/api/wordfence/update", methods=["POST"])
def api_wordfence_update():
    global _wordfence_update_running

    if _wordfence_update_running:
        return jsonify({"error": "Wordfence update already in progress."}), 409

    api_key = get_wordfence_api_key()
    if not api_key:
        return jsonify({"error": "Wordfence API key is not configured."}), 400

    _wordfence_update_running = True

    def run_update():
        global _wordfence_update_running
        try:
            with app.app_context():
                refresh_wordfence_cache(get_wordfence_api_key(), force=True)
        except WordfenceCacheError as e:
            app.logger.warning("Wordfence update failed: %s", e)
        finally:
            _wordfence_update_running = False

    socketio.start_background_task(run_update)
    return jsonify({"ok": True, "message": "Wordfence database update started."})


@app.route("/api/settings/test-proxy", methods=["POST"])
def api_test_proxy():
    data = request.get_json(silent=True) or {}
    proxy_url = (data.get("url") or "").strip()
    if not proxy_url:
        return jsonify({"error": "Proxy URL is required."}), 400
    try:
        import requests

        res = requests.get(
            "https://httpbin.org/ip",
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=15,
        )
        if res.status_code == 200:
            return jsonify({"ok": True, "message": "Proxy connection successful.", "ip": res.json()})
        return jsonify({"error": f"Proxy returned status {res.status_code}."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/settings/test-ai", methods=["POST"])
def api_test_ai():
    data = request.get_json(silent=True) or {}
    override = None
    if data.get("ai"):
        current = get_settings()
        override = merge_ai_config(current["ai"], data["ai"])
    try:
        result = test_ai_connection(override_cfg=override)
        return jsonify(result)
    except AIAnalyzerError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.exception("AI test failed")
        return jsonify({"error": f"Connection test failed: {e}"}), 400


@app.route("/api/settings/ai-models", methods=["POST"])
def api_fetch_ai_models():
    data = request.get_json(silent=True) or {}
    ai = data.get("ai") or data
    current = get_settings().get("ai", {})

    base_url = (ai.get("base_url") or current.get("base_url") or "").strip()
    provider = ai.get("provider") or current.get("provider", "custom")
    api_key = ai.get("api_key") or current.get("api_key", "")

    if not base_url:
        return jsonify({"error": "Base URL is required."}), 400

    try:
        models = fetch_available_models(base_url, api_key=api_key, provider=provider)
        return jsonify({"models": models})
    except AIAnalyzerError as e:
        return jsonify({"error": str(e)}), 400


def _make_ai_progress_emitter(sid, flush_interval=0.07, min_chunk=48):
    """Batch AI stream chunks so the UI updates smoothly without waiting for completion."""
    buffers = {"thinking": "", "content": ""}
    last_flush = {"thinking": 0.0, "content": 0.0}

    def _emit(phase):
        chunk = buffers[phase]
        if not chunk:
            return
        buffers[phase] = ""
        if phase == "thinking":
            socketio.emit("ai_analysis_thinking", {"chunk": chunk}, to=sid)
        elif phase == "content":
            socketio.emit("ai_analysis_chunk", {"chunk": chunk}, to=sid)

    def on_ai_progress(phase, text):
        if not text or phase not in buffers:
            return
        buffers[phase] += text
        now = time.monotonic()
        if now - last_flush[phase] >= flush_interval or len(buffers[phase]) >= min_chunk:
            last_flush[phase] = now
            _emit(phase)

    def flush_all():
        for phase in buffers:
            _emit(phase)

    return on_ai_progress, flush_all


def _run_ai_analysis(sid, scan_data, ai_override=None, emit_start=True):
    """Run AI analysis in background and stream thinking/content chunks to the client."""

    def log_progress(message, type="info"):
        socketio.emit("log", {"message": message, "type": type}, to=sid)

    if emit_start:
        with app.app_context():
            ai_cfg = merge_ai_config(get_settings().get("ai", {}), ai_override)
        thinking_mode = is_thinking_model(ai_cfg.get("model", ""))
        socketio.emit("ai_analysis_start", {"thinking_mode": thinking_mode, "streaming": True}, to=sid)

    on_ai_progress, flush_ai_progress = _make_ai_progress_emitter(sid)

    try:
        with app.app_context():
            analysis = analyze_scan_results(
                scan_data,
                progress_callback=on_ai_progress,
                cfg_override=ai_override,
            )
        flush_ai_progress()
        analysis = finalize_analysis_result(analysis)
        _analysis_results_by_sid[sid] = analysis
        socketio.emit("ai_analysis_complete", {"ready": True}, to=sid)
        log_progress("AI security analysis completed.", "success")
    except AIAnalyzerError as e:
        socketio.emit("ai_analysis_error", {"message": str(e)}, to=sid)
        log_progress(f"AI analysis failed: {e}", "error")
    except Exception as e:
        socketio.emit("ai_analysis_error", {"message": f"Unexpected error: {e}"}, to=sid)
        log_progress(f"AI analysis failed: {e}", "error")
        app.logger.exception("AI analysis failed")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    sid = (data.get("sid") or "").strip()
    ai_override = data.get("ai")
    scan_data = _resolve_scan_data(sid, data.get("results"))

    if not sid:
        return jsonify({"error": "Socket session ID is required."}), 400
    if not scan_data:
        return jsonify({"error": "Scan results are required. Run a scan first."}), 400

    try:
        ai_cfg = _validate_ai_request(ai_override)
    except AIAnalyzerError as e:
        return jsonify({"error": str(e)}), 400

    thinking_mode = is_thinking_model(ai_cfg.get("model", ""))
    socketio.emit("ai_analysis_start", {"thinking_mode": thinking_mode, "streaming": True}, to=sid)
    socketio.start_background_task(_run_ai_analysis, sid, scan_data, ai_override, False)
    return jsonify({"ok": True, "thinking_mode": thinking_mode})


@app.route("/api/analyze/result", methods=["GET"])
def api_analyze_result():
    sid = (request.args.get("sid") or "").strip()
    if not sid:
        return jsonify({"error": "Socket session ID is required."}), 400
    result = _analysis_results_by_sid.get(sid)
    if not result:
        return jsonify({"error": "Analysis result not ready."}), 404
    return jsonify(result)


@app.route("/api/export/pdf", methods=["POST"])
def api_export_pdf():
    data = request.get_json(silent=True) or {}
    lang = (data.get("lang") or "en").strip().lower()
    if lang not in ("en", "fa"):
        lang = "en"
    include_ai = bool(data.get("include_ai"))
    sid = (data.get("sid") or "").strip()

    scan_data = _resolve_scan_data(sid, data.get("results"))
    if not scan_data:
        return jsonify({"error": "Scan results are required. Run a scan first."}), 400

    analysis_text = (data.get("analysis") or "").strip()
    ai_meta = data.get("ai_meta") or {}
    if include_ai and not analysis_text and sid:
        stored = _analysis_results_by_sid.get(sid) or {}
        analysis_text = (stored.get("analysis") or "").strip()
        ai_meta = {
            "model": stored.get("model"),
            "provider": stored.get("provider"),
        }

    if include_ai and not analysis_text:
        return jsonify({"error": "AI analysis is not available. Run AI analysis first or export without AI."}), 400

    try:
        pdf_bytes = generate_pdf(
            scan_data,
            lang=lang,
            analysis=analysis_text if include_ai else None,
            ai_meta=ai_meta if include_ai else None,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.exception("PDF export failed")
        return jsonify({"error": f"PDF generation failed: {e}"}), 500

    host = urlparse(scan_data.get("url") or "scan").netloc or "scan"
    safe_host = "".join(c if c.isalnum() or c in ".-" else "_" for c in host)
    suffix = "ai" if include_ai else "scan"
    filename = f"wp-guard-{safe_host}-{suffix}-{lang}.pdf"
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )

@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def delete_history(scan_id):
    scan = db.session.get(ScanResult, scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"ok": True})


def run_scan(sid, target_url):
    """Run a (blocking) scan inside a background greenlet so the socket stays responsive."""

    def log_progress(log_data):
        socketio.emit("log", log_data, to=sid)

    def scan_progress(payload):
        socketio.emit("scan_partial", payload, to=sid)

    try:
        with app.app_context():
            settings = get_settings()
            proxies = get_proxy_dict()

        if settings.get("proxy", {}).get("enabled") and proxies:
            log_progress({"message": f"Routing traffic through proxy: {proxies['http']}", "type": "info"})

        log_progress({
            "message": "Authorized use only — scan targets you own or have explicit written permission to test.",
            "type": "warning",
        })

        scanner = WordPressScanner(
            target_url,
            log_callback=log_progress,
            progress_callback=scan_progress,
            proxies=proxies,
            scan_config=settings.get("scan"),
        )
        results = scanner.scan()

        with app.app_context():
            new_scan = ScanResult(
                url=target_url,
                version=results["version"],
                data_json=json.dumps(results),
            )
            db.session.add(new_scan)
            db.session.commit()
            ai_cfg = get_settings().get("ai", {})

        socketio.emit("scan_complete", results, to=sid)
        _remember_scan(sid, results)

        if ai_cfg.get("enabled") and ai_cfg.get("auto_analyze"):
            log_progress({"message": "Sending results to AI for security analysis...", "type": "info"})
            socketio.start_background_task(_run_ai_analysis, sid, results)
    except Exception as e:
        socketio.emit("log", {"message": f"Scan failed: {e}", "type": "error"}, to=sid)
        socketio.emit("scan_error", {"message": str(e)}, to=sid)


@socketio.on("request_ai_analysis")
def handle_request_ai_analysis(data):
    sid = request.sid
    scan_data = _resolve_scan_data(sid, (data or {}).get("results"))
    if not scan_data:
        emit("ai_analysis_error", {"message": "Scan results are required."})
        return
    ai_override = (data or {}).get("ai")
    try:
        ai_cfg = _validate_ai_request(ai_override)
    except AIAnalyzerError as e:
        emit("ai_analysis_error", {"message": str(e)})
        return
    thinking_mode = is_thinking_model(ai_cfg.get("model", ""))
    emit("ai_analysis_start", {"thinking_mode": thinking_mode, "streaming": True})
    socketio.start_background_task(_run_ai_analysis, sid, scan_data, ai_override, False)


@socketio.on("start_scan")
def handle_scan(data):
    target_url = normalize_url((data or {}).get("url"))
    if not target_url:
        emit("log", {"message": "Invalid or missing URL.", "type": "error"})
        emit("scan_error", {"message": "Invalid URL"})
        return

    socketio.start_background_task(run_scan, request.sid, target_url)


if __name__ == "__main__":
    print("Authorized use only — scan sites you own or have written permission to test.")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
