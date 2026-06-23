"""Generate bilingual PDF security reports from scan results."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from runtime_paths import resource_root

PERSIAN_FONT_PATH = os.path.join(resource_root(), "static", "fonts", "Vazirmatn-Regular.ttf")

LABELS = {
    "en": {
        "title": "WP Guard Security Report",
        "subtitle": "WordPress vulnerability assessment",
        "target": "Target",
        "generated": "Generated",
        "duration": "Scan duration",
        "version": "WordPress version",
        "summary": "Executive Summary",
        "severity": "Severity breakdown",
        "findings": "Findings",
        "plugins": "Plugins",
        "themes": "Themes",
        "users": "Discovered users",
        "auth_surface": "Authentication surface",
        "wp_admin": "wp-admin reachable",
        "xmlrpc": "XML-RPC enabled",
        "yes": "Yes",
        "no": "No",
        "none": "None detected",
        "ai_section": "AI Security Analysis",
        "ai_model": "Model",
        "ai_provider": "Provider",
        "disclaimer": "Authorized use only. This report is for security testing on systems you own or are explicitly authorized to assess.",
        "footer": "WP Guard · Authorized testing only · Do not use without permission",
        "seconds": "seconds",
    },
    "fa": {
        "title": "گزارش امنیتی WP Guard",
        "subtitle": "ارزیابی آسیب‌پذیری وردپرس",
        "target": "هدف",
        "generated": "تاریخ تولید",
        "duration": "مدت اسکن",
        "version": "نسخه وردپرس",
        "summary": "خلاصه اجرایی",
        "severity": "توزیع شدت",
        "findings": "یافته‌ها",
        "plugins": "افزونه‌ها",
        "themes": "پوسته‌ها",
        "users": "کاربران کشف‌شده",
        "auth_surface": "سطح احراز هویت",
        "wp_admin": "دسترسی wp-admin",
        "xmlrpc": "XML-RPC فعال",
        "yes": "بله",
        "no": "خیر",
        "none": "موردی یافت نشد",
        "ai_section": "تحلیل امنیتی هوش مصنوعی",
        "ai_model": "مدل",
        "ai_provider": "ارائه‌دهنده",
        "disclaimer": "فقط استفاده مجاز. این گزارش برای تست امنیتی سایت‌هایی است که مالک آن‌ها هستید یا مجوز کتبی دارید.",
        "footer": "WP Guard · فقط تست مجاز · بدون اجازه استفاده نکنید",
        "seconds": "ثانیه",
    },
}

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


def _labels(lang: str) -> dict:
    return LABELS.get(lang, LABELS["en"])


def _strip_markdown(text: str) -> str:
    if not text:
        return ""
    lines = []
    for line in text.splitlines():
        line = re.sub(r"^#{1,6}\s+", "", line)
        line = re.sub(r"\*\*(.+?)\*\*", r"\1", line)
        line = re.sub(r"`([^`]+)`", r"\1", line)
        line = re.sub(r"^\s*[-*+]\s+", "• ", line)
        line = re.sub(r"^\d+\.\s+", "• ", line)
        lines.append(line)
    return "\n".join(lines).strip()


class ReportPDF(FPDF):
    def __init__(self, lang: str):
        super().__init__()
        self.lang = lang
        self.labels = _labels(lang)
        self._use_persian = lang == "fa"
        if self._use_persian and os.path.isfile(PERSIAN_FONT_PATH):
            self.add_font("Vazir", "", PERSIAN_FONT_PATH)
            self.add_font("Vazir", "B", PERSIAN_FONT_PATH)
        self.set_auto_page_break(auto=True, margin=18)

    def _font(self, style: str = "", size: int = 10):
        if self._use_persian and os.path.isfile(PERSIAN_FONT_PATH):
            self.set_font("Vazir", style, size)
        else:
            self.set_font("Helvetica", style, size)

    def header(self):
        self._font("B", 14)
        self.cell(0, 8, self.labels["title"], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self._font("", 9)
        self.set_text_color(90, 90, 90)
        self.cell(0, 6, self.labels["subtitle"], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def footer(self):
        self.set_y(-14)
        self._font("", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, self.labels["footer"], align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def section_title(self, title: str):
        self.ln(3)
        self._font("B", 11)
        self.set_fill_color(240, 242, 245)
        self.cell(0, 8, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.ln(1)

    def body_text(self, text: str):
        self._font("", 9)
        self.multi_cell(0, 5, text or self.labels["none"], new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def key_value(self, key: str, value: str):
        self._font("", 9)
        self.multi_cell(0, 6, f"{key}: {value or '-'}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _format_user(user) -> str:
    if isinstance(user, dict):
        name = user.get("username") or user.get("slug") or user.get("name") or "?"
        source = user.get("source")
        return f"{name} ({source})" if source else str(name)
    return str(user)


def _risk_level(results: dict) -> str:
    counts = results.get("severity_counts") or {}
    if counts.get("Critical"):
        return "Critical"
    if counts.get("High"):
        return "High"
    if counts.get("Medium"):
        return "Medium"
    vulns = results.get("vulnerabilities") or []
    if vulns:
        return "Medium"
    return "Low"


def generate_pdf(
    results: dict,
    *,
    lang: str = "en",
    analysis: str | None = None,
    ai_meta: dict | None = None,
) -> bytes:
    """Build a PDF report and return raw bytes."""
    if not results:
        raise ValueError("Scan results are required.")

    lang = lang if lang in LABELS else "en"
    labels = _labels(lang)
    pdf = ReportPDF(lang)
    pdf.add_page()

    target = results.get("url") or "-"
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    duration = results.get("duration")
    duration_text = f"{duration:.1f} {labels['seconds']}" if isinstance(duration, (int, float)) else "-"

    pdf.key_value(labels["target"], target)
    pdf.key_value(labels["generated"], generated_at)
    pdf.key_value(labels["duration"], duration_text)
    pdf.key_value(labels["version"], str(results.get("version") or "Unknown"))

    pdf.section_title("Notice" if lang == "en" else "تذکر")
    pdf.body_text(labels["disclaimer"])

    counts = results.get("severity_counts") or {}
    vulns = results.get("vulnerabilities") or []
    if not counts and vulns:
        counts = {}
        for v in vulns:
            sev = v.get("severity") or "Info"
            counts[sev] = counts.get(sev, 0) + 1

    pdf.section_title(labels["summary"])
    risk = _risk_level(results)
    summary_lines = [
        f"{labels['findings']}: {len(vulns)}",
        f"Risk: {risk}" if lang == "en" else f"ریسک: {risk}",
    ]
    pdf.body_text("\n".join(summary_lines))

    if counts:
        pdf.section_title(labels["severity"])
        parts = [f"{sev}: {counts.get(sev, 0)}" for sev in SEVERITY_ORDER if counts.get(sev)]
        pdf.body_text(" · ".join(parts))

    auth = results.get("auth_surface") or {}
    if auth:
        pdf.section_title(labels["auth_surface"])
        yes, no = labels["yes"], labels["no"]
        pdf.body_text(
            f"{labels['wp_admin']}: {yes if auth.get('wp_admin') else no}\n"
            f"{labels['xmlrpc']}: {yes if auth.get('xmlrpc') else no}"
        )

    users = results.get("users") or []
    if users:
        pdf.section_title(labels["users"])
        pdf.body_text("\n".join(_format_user(u) for u in users[:25]))

    plugins = results.get("plugins") or []
    if plugins:
        pdf.section_title(labels["plugins"])
        lines = []
        for p in plugins[:30]:
            slug = p.get("slug", "?")
            ver = p.get("version", "?")
            extra = ""
            if p.get("vulnerable"):
                extra = " [CVE]"
            elif p.get("outdated"):
                extra = " [outdated]"
            lines.append(f"• {slug} v{ver}{extra}")
        pdf.body_text("\n".join(lines))

    themes = results.get("themes") or []
    if themes:
        pdf.section_title(labels["themes"])
        lines = [f"• {t.get('slug', '?')} v{t.get('version', '?')}" for t in themes[:20]]
        pdf.body_text("\n".join(lines))

    if vulns:
        pdf.section_title(labels["findings"])
        for v in vulns[:60]:
            name = v.get("name") or "Finding"
            sev = v.get("severity") or "Info"
            desc = (v.get("description") or "").strip()
            pdf._font("B", 9)
            pdf.multi_cell(0, 5, f"[{sev}] {name}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if desc:
                pdf._font("", 8)
                pdf.multi_cell(0, 4, desc[:1200], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)

    updates = results.get("update_recommendations") or []
    if updates:
        pdf.section_title("Update recommendations" if lang == "en" else "توصیه به‌روزرسانی")
        for u in updates[:40]:
            name = u.get("name") or "Update"
            desc = (u.get("description") or "").strip()
            pdf._font("B", 9)
            pdf.multi_cell(0, 5, name, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if desc:
                pdf._font("", 8)
                pdf.multi_cell(0, 4, desc[:800], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)

    if analysis:
        pdf.add_page()
        pdf.section_title(labels["ai_section"])
        meta = ai_meta or {}
        if meta.get("model") or meta.get("provider"):
            meta_line = []
            if meta.get("provider"):
                meta_line.append(f"{labels['ai_provider']}: {meta['provider']}")
            if meta.get("model"):
                meta_line.append(f"{labels['ai_model']}: {meta['model']}")
            pdf.body_text(" · ".join(meta_line))
            pdf.ln(2)
        pdf.body_text(_strip_markdown(analysis))

    out = pdf.output()
    return out if isinstance(out, (bytes, bytearray)) else out.encode("latin-1")
