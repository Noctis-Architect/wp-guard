import json

import requests

from settings_manager import get_settings

AI_ANALYZE_TIMEOUT = 120
AI_TEST_TIMEOUT = 30

THINKING_MODEL_HINTS = ("think", "r1", "qwq", "qwen3", "deepseek", "o1", "o3", "reason")


class AIAnalyzerError(Exception):
    pass


def is_thinking_model(model_id):
    low = (model_id or "").lower()
    return any(hint in low for hint in THINKING_MODEL_HINTS)


def _build_headers(api_key):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _request_kwargs(timeout):
    """AI calls intentionally bypass the scan proxy (Ollama/localhost would break)."""
    connect = min(10, max(3, timeout // 3))
    return {"timeout": (connect, timeout)}


def _normalize_base_url(base_url):
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise AIAnalyzerError("AI base URL is not configured.")
    return base


def _ollama_root_url(base_url):
    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        return root[:-3]
    return root


def _is_likely_chat_model(model_id):
    low = (model_id or "").lower()
    skip = ("embed", "tts", "whisper", "dall-e", "moderation", "davinci", "babbage", "curie", "ada", "realtime")
    return model_id and not any(token in low for token in skip)


def _persian_char_count(value):
    return sum(1 for ch in (value or "") if "\u0600" <= ch <= "\u06FF")


def _repair_utf8_mojibake(text):
    """Fix UTF-8 text that was incorrectly decoded as Latin-1 (common in SSE streams)."""
    if not text or not isinstance(text, str):
        return text
    if _persian_char_count(text) and not any(marker in text for marker in ("Ø", "Ù", "Ú", "Û", "Ã", "Â", "â")):
        return text
    for encoding in ("latin-1", "iso-8859-1"):
        try:
            repaired = text.encode(encoding).decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        if _persian_char_count(repaired) > 0:
            return repaired
        if any(marker in text for marker in ("Ø", "Ù", "Ú", "Û", "Ã", "Â", "â")) and _persian_char_count(repaired) >= _persian_char_count(text):
            return repaired
    return text


def finalize_ai_text(text):
    return _repair_utf8_mojibake((text or "").strip())


def finalize_analysis_result(result):
    out = dict(result or {})
    if "analysis" in out:
        out["analysis"] = finalize_ai_text(out.get("analysis"))
    if out.get("thinking"):
        out["thinking"] = finalize_ai_text(out.get("thinking"))
    return out


def _raw_text_from_content(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(_raw_text_from_content(item) for item in value)
    if isinstance(value, dict):
        return _raw_text_from_content(value.get("text") or value.get("content"))
    return str(value)


def _text_from_content(value):
    """Normalize API content structure without per-chunk encoding repair."""
    return _raw_text_from_content(value)


def _iter_sse_chunks(response):
    """Yield JSON objects from an SSE/NDJSON byte stream."""
    for raw_line in response.iter_lines(decode_unicode=False):
        if not raw_line:
            continue
        line = raw_line.strip()
        if line.startswith(b"data:"):
            line = line[5:].strip()
        if not line or line == b"[DONE]":
            continue
        try:
            yield json.loads(line)
        except (ValueError, UnicodeDecodeError):
            try:
                yield json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue


def _read_response_text(response, limit=500):
    try:
        text = response.content.decode("utf-8")
    except UnicodeDecodeError:
        text = response.content.decode("utf-8", errors="replace")
    return _repair_utf8_mojibake(text[:limit])


def _fetch_openai_compatible_models(base_url, api_key):
    url = f"{base_url}/models"
    try:
        res = requests.get(url, headers=_build_headers(api_key), **_request_kwargs(15))
        if res.status_code != 200:
            return []
        data = res.json()
        models = []
        if isinstance(data.get("data"), list):
            models = [m["id"] for m in data["data"] if isinstance(m, dict) and m.get("id")]
        return [m for m in models if _is_likely_chat_model(m)]
    except requests.RequestException:
        return []


def _fetch_ollama_native_models(base_url):
    url = f"{_ollama_root_url(base_url)}/api/tags"
    try:
        res = requests.get(url, **_request_kwargs(15))
        if res.status_code != 200:
            return []
        return [m["name"] for m in res.json().get("models", []) if m.get("name")]
    except requests.RequestException:
        return []


def fetch_available_models(base_url, api_key="", provider="custom"):
    """Return sorted model IDs from an OpenAI-compatible or Ollama provider."""
    base_url = _normalize_base_url(base_url)
    api_key = (api_key or "").strip()
    provider = (provider or "custom").lower()

    if provider != "ollama" and not api_key:
        raise AIAnalyzerError("API key is required to fetch models from this provider.")

    models = _fetch_openai_compatible_models(base_url, api_key)
    if not models and provider == "ollama":
        models = _fetch_ollama_native_models(base_url)

    models = sorted(set(models), key=str.lower)
    if not models:
        raise AIAnalyzerError("No models found. Check Base URL, API key, and provider settings.")
    return models


def _extract_message_fields(message):
    """Pull final answer and optional thinking/reasoning from an API message object."""
    if not isinstance(message, dict):
        return "", ""

    content = _text_from_content(message.get("content")).strip()
    thinking = (
        message.get("reasoning_content")
        or message.get("thinking")
        or message.get("reasoning")
        or ""
    )
    if isinstance(thinking, list):
        thinking = "".join(_text_from_content(part) for part in thinking)
    thinking = _text_from_content(thinking).strip()

    if not content and thinking:
        content, thinking = thinking, ""

    return content, thinking


def _build_analyze_payload(model, system_prompt, user_content, provider):
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.3,
    }
    if provider == "ollama" and is_thinking_model(model):
        payload["think"] = True
    return payload


def _parse_stream_chunk(raw_line):
    if raw_line is None:
        return None
    if isinstance(raw_line, bytes):
        line = raw_line.strip()
        if line.startswith(b"data:"):
            line = line[5:].strip()
        if not line or line == b"[DONE]":
            return None
        try:
            return json.loads(line)
        except (ValueError, UnicodeDecodeError):
            return None
    line = raw_line.strip()
    if line.startswith("data:"):
        line = line[5:].strip()
    if not line or line == "[DONE]":
        return None
    try:
        return json.loads(line)
    except ValueError:
        return None


def _collect_stream_delta(delta, message, thinking_parts, content_parts, progress_callback):
    for key in ("thinking", "reasoning_content", "reasoning"):
        piece = _text_from_content(delta.get(key) or message.get(key))
        if piece:
            thinking_parts.append(piece)
            if progress_callback:
                progress_callback("thinking", piece)

    piece = _text_from_content(delta.get("content") or message.get("content"))
    if piece:
        content_parts.append(piece)
        if progress_callback:
            progress_callback("content", piece)


def _process_stream_chunk(chunk, thinking_parts, content_parts, progress_callback):
    if not isinstance(chunk, dict):
        return

    choices = chunk.get("choices") or []
    if choices:
        choice = choices[0]
        delta = choice.get("delta") or {}
        message = choice.get("message") or {}
        _collect_stream_delta(delta, message, thinking_parts, content_parts, progress_callback)
        return

    message = chunk.get("message") or {}
    if message:
        _collect_stream_delta({}, message, thinking_parts, content_parts, progress_callback)


def _analyze_streaming(url, headers, payload, timeout, progress_callback=None):
    payload = {**payload, "stream": True}
    thinking_parts = []
    content_parts = []

    try:
        with requests.post(
            url,
            headers=headers,
            json=payload,
            stream=True,
            **_request_kwargs(timeout),
        ) as res:
            if res.status_code != 200:
                detail = _read_response_text(res, 500)
                raise AIAnalyzerError(f"AI API returned {res.status_code}: {detail}")

            for chunk in _iter_sse_chunks(res):
                if not chunk:
                    continue
                _process_stream_chunk(chunk, thinking_parts, content_parts, progress_callback)
    except requests.RequestException as e:
        raise AIAnalyzerError(f"Could not reach AI API: {e}") from e

    thinking = finalize_ai_text("".join(thinking_parts))
    content = finalize_ai_text("".join(content_parts))
    if not content and thinking:
        content, thinking = thinking, ""
    if not content:
        raise AIAnalyzerError("AI API returned an empty response.")
    return content, thinking


def _analyze_ollama_native(base_url, model, system_prompt, user_content, timeout, progress_callback=None):
    url = f"{_ollama_root_url(base_url)}/api/chat"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "stream": True,
    }
    thinking_parts = []
    content_parts = []

    try:
        with requests.post(url, json=payload, stream=True, **_request_kwargs(timeout)) as res:
            if res.status_code != 200:
                raise AIAnalyzerError(f"Ollama API returned {res.status_code}: {_read_response_text(res, 500)}")

            for chunk in _iter_sse_chunks(res):
                if not chunk:
                    continue
                _process_stream_chunk(chunk, thinking_parts, content_parts, progress_callback)
    except requests.RequestException as e:
        raise AIAnalyzerError(f"Could not reach Ollama: {e}") from e

    thinking = finalize_ai_text("".join(thinking_parts))
    content = finalize_ai_text("".join(content_parts))
    if not content and thinking:
        content, thinking = thinking, ""
    if not content:
        raise AIAnalyzerError("Ollama returned an empty response.")
    return content, thinking


def _analyze_non_streaming(url, headers, payload, timeout, progress_callback=None):
    try:
        res = requests.post(url, headers=headers, json=payload, **_request_kwargs(timeout))
    except requests.RequestException as e:
        raise AIAnalyzerError(f"Could not reach AI API: {e}") from e

    if res.status_code != 200:
        raise AIAnalyzerError(f"AI API returned {res.status_code}: {_read_response_text(res, 500)}")

    data = json.loads(res.content)
    choices = data.get("choices") or []
    if not choices:
        raise AIAnalyzerError("AI API returned an empty response.")

    message = choices[0].get("message") or {}
    content, thinking = _extract_message_fields(message)
    content = finalize_ai_text(content)
    thinking = finalize_ai_text(thinking)
    if thinking and progress_callback:
        progress_callback("thinking", thinking)
    if content and progress_callback:
        progress_callback("content", content)
    if not content:
        raise AIAnalyzerError("AI API returned an empty response.")
    return content, thinking


def _build_version_vuln_summary(scan_results):
    """Compact version/CVE context for the AI prompt."""
    lines = ["## Detected versions & CVE lookup summary", ""]

    wp_version = scan_results.get("version") or "Unknown"
    core = scan_results.get("core_version_status") or {}
    lines.append(f"- **WordPress core**: {wp_version}")
    if core.get("latest_version"):
        status = "OUTDATED" if core.get("outdated") else "up to date"
        lines.append(f"  - Latest: {core['latest_version']} ({status})")

    plugins = scan_results.get("plugins") or []
    if plugins:
        lines.append("- **Plugins**:")
        for p in plugins:
            slug = p.get("slug", "?")
            ver = p.get("version", "?")
            latest = p.get("latest_version")
            vuln_count = len(p.get("known_vulnerabilities") or [])
            flags = []
            if p.get("vulnerable"):
                flags.append(f"{vuln_count} known CVE(s) for this version")
            elif p.get("outdated"):
                flags.append(f"outdated, latest v{latest}")
            elif latest:
                flags.append("up to date")
            flag_text = f" — {', '.join(flags)}" if flags else ""
            lines.append(f"  - {slug} v{ver}{flag_text}")
            for v in (p.get("known_vulnerabilities") or [])[:3]:
                lines.append(f"    - [{v.get('severity', '?')}] {v.get('title', '')}")

    themes = scan_results.get("themes") or []
    if themes:
        lines.append("- **Themes**:")
        for t in themes:
            slug = t.get("slug", "?")
            ver = t.get("version", "?")
            latest = t.get("latest_version")
            vuln_count = len(t.get("known_vulnerabilities") or [])
            flags = []
            if t.get("vulnerable"):
                flags.append(f"{vuln_count} known CVE(s) for this version")
            elif t.get("outdated"):
                flags.append(f"outdated, latest v{latest}")
            elif latest:
                flags.append("up to date")
            flag_text = f" — {', '.join(flags)}" if flags else ""
            lines.append(f"  - {slug} v{ver}{flag_text}")
            for v in (t.get("known_vulnerabilities") or [])[:3]:
                lines.append(f"    - [{v.get('severity', '?')}] {v.get('title', '')}")

    comp_vulns = scan_results.get("component_vulnerabilities") or []
    if comp_vulns:
        lines.append("")
        lines.append(
            f"Total confirmed version-specific vulnerabilities from WPScan lookup: {len(comp_vulns)}"
        )

    dyn_findings = scan_results.get("dynamic_analysis_findings") or []
    confirmed_dyn = [f for f in dyn_findings if f.get("verified")]
    if dyn_findings:
        lines.append("")
        lines.append(f"Dynamic PoC verification: {len(confirmed_dyn)} live-confirmed / {len(dyn_findings)} probed")
        for f in confirmed_dyn[:5]:
            lines.append(
                f"  - LIVE [{f.get('category', '?').upper()}] {f.get('component_slug')} — {f.get('vuln_title')}"
            )

    lines.append("")
    lines.append(
        "For each component above, assess whether the installed version has a **dangerous exploitable bug** "
        "and recommend immediate patching if so."
    )
    return "\n".join(lines)


def merge_ai_config(base_cfg, override=None):
    """Merge optional client-side AI overrides, keeping saved API key when form field is blank."""
    cfg = dict(base_cfg or {})
    if not override:
        return cfg
    merged = {**cfg, **override}
    if not (override.get("api_key") or "").strip():
        merged["api_key"] = cfg.get("api_key", "")
    return merged


def _run_chat_completion(cfg, system_prompt, user_content, timeout, progress_callback=None):
    base_url = _normalize_base_url(cfg.get("base_url"))
    model = (cfg.get("model") or "").strip()
    api_key = (cfg.get("api_key") or "").strip()
    provider = (cfg.get("provider") or "custom").lower()

    payload = _build_analyze_payload(model, system_prompt, user_content, provider)
    url = f"{base_url}/chat/completions"
    headers = _build_headers(api_key)

    errors = []
    for attempt in (
        lambda: _analyze_streaming(url, headers, payload, timeout, progress_callback),
        lambda: _analyze_non_streaming(url, headers, payload, timeout, progress_callback),
    ):
        try:
            return attempt()
        except AIAnalyzerError as e:
            errors.append(str(e))

    if provider == "ollama":
        try:
            return _analyze_ollama_native(
                base_url, model, system_prompt, user_content, timeout, progress_callback
            )
        except AIAnalyzerError as e:
            errors.append(str(e))

    detail = errors[-1] if errors else "Unknown AI error."
    raise AIAnalyzerError(detail)


def analyze_scan_results(scan_results, custom_prompt=None, progress_callback=None, cfg_override=None):
    """Send scan results to an OpenAI-compatible chat API (OpenAI, Ollama, etc.)."""
    cfg = merge_ai_config(get_settings().get("ai", {}), cfg_override)
    if not cfg.get("enabled"):
        raise AIAnalyzerError("AI analysis is disabled.")

    model = (cfg.get("model") or "").strip()
    if not model:
        raise AIAnalyzerError("AI model is not configured.")

    provider = cfg.get("provider", "custom")
    api_key = (cfg.get("api_key") or "").strip()
    if provider != "ollama" and not api_key:
        raise AIAnalyzerError("API key is required for this provider.")

    system_prompt = custom_prompt or cfg.get("system_prompt") or ""

    version_summary = _build_version_vuln_summary(scan_results)
    user_content = (
        "Analyze the following WordPress security scan results and provide your full security assessment.\n\n"
        "Pay special attention to **installed component versions** and whether they have **known dangerous "
        "vulnerabilities (CVE/RCE/SQLi/auth bypass)**. Use the `known_vulnerabilities` and "
        "`component_vulnerabilities` fields from the lookup. For each affected plugin/theme/core version, "
        "clearly state if it is exploitable and how severe the risk is.\n\n"
        f"{version_summary}\n\n"
        "Full scan JSON:\n"
        "```json\n"
        f"{json.dumps(scan_results, indent=2, ensure_ascii=False, default=str)}\n"
        "```"
    )

    content, thinking = _run_chat_completion(
        cfg, system_prompt, user_content, AI_ANALYZE_TIMEOUT, progress_callback
    )

    result = finalize_analysis_result({
        "analysis": content,
        "model": model,
        "provider": provider,
        "streaming": True,
        "thinking_mode": is_thinking_model(model),
        **({"thinking": thinking} if thinking else {}),
    })
    return result


def _test_ollama_native(base_url, model):
    url = f"{_ollama_root_url(base_url)}/api/chat"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
        "stream": False,
    }
    res = requests.post(url, json=payload, **_request_kwargs(AI_TEST_TIMEOUT))
    if res.status_code != 200:
        raise AIAnalyzerError(f"Ollama connection failed ({res.status_code}): {_read_response_text(res, 300)}")
    return {"ok": True, "message": "Ollama connection successful."}


def test_ai_connection(override_cfg=None):
    """Quick connectivity check against the configured AI endpoint."""
    cfg = override_cfg if override_cfg is not None else get_settings().get("ai", {})
    base_url = _normalize_base_url(cfg.get("base_url"))
    model = (cfg.get("model") or "").strip()
    if not model:
        raise AIAnalyzerError("AI model is not configured.")

    api_key = (cfg.get("api_key") or "").strip()
    provider = (cfg.get("provider") or "custom").lower()
    if provider != "ollama" and not api_key:
        raise AIAnalyzerError("API key is required for this provider.")

    if provider == "ollama":
        root = _ollama_root_url(base_url)
        try:
            ping = requests.get(f"{root}/api/tags", **_request_kwargs(10))
            if ping.status_code != 200:
                raise AIAnalyzerError(f"Ollama is not reachable ({ping.status_code}). Is it running?")
        except requests.RequestException as e:
            raise AIAnalyzerError(f"Could not reach Ollama at {root}: {e}") from e

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
        "max_tokens": 32,
        "stream": False,
    }

    url = f"{base_url}/chat/completions"
    try:
        res = requests.post(
            url,
            headers=_build_headers(api_key),
            json=payload,
            **_request_kwargs(AI_TEST_TIMEOUT),
        )
        if res.status_code == 200:
            return {"ok": True, "message": "AI connection successful."}
        if provider == "ollama":
            return _test_ollama_native(base_url, model)
        raise AIAnalyzerError(f"Connection failed ({res.status_code}): {_read_response_text(res, 300)}")
    except requests.RequestException as e:
        if provider == "ollama":
            return _test_ollama_native(base_url, model)
        raise AIAnalyzerError(f"Could not reach AI API: {e}") from e
