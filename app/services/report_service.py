"""
Report service: generates a PDF incident report for an event.

The response agent calls generate_report(state) for high-risk incidents. The
layout follows the incident-report structure validated in the FYP1 prototype:
Alert Details / AI Analysis / Attack Chain / Response Actions.
"""
import os
import textwrap
from datetime import datetime

from config.settings import settings

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas as _canvas
except ImportError:
    _canvas = None

_PAGE_W, _PAGE_H = (595, 842)   # A4 in points; only used when reportlab exists


class _Writer:
    """Tiny helper: wrapped text lines with automatic page breaks."""

    def __init__(self, c):
        self.c = c
        self.y = _PAGE_H - 50

    def _ensure_room(self, needed=20):
        if self.y < 60:
            self.c.showPage()
            self.y = _PAGE_H - 50

    def heading(self, text, size=14):
        self._ensure_room(30)
        self.y -= 10
        self.c.setFont("Helvetica-Bold", size)
        self.c.drawString(50, self.y, text)
        self.y -= 20

    def line(self, label, value):
        self.c.setFont("Helvetica", 10)
        for chunk in textwrap.wrap(f"{label}: {value}", width=95) or [f"{label}:"]:
            self._ensure_room()
            self.c.drawString(60, self.y, chunk)
            self.y -= 14


def generate_report(state: dict) -> str:
    os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
    filename = f"CyREN_Incident_{state.get('source_ip','unknown')}_{ts}.pdf"
    path = os.path.join(settings.REPORT_OUTPUT_DIR, filename)

    if _canvas is None:
        # skeleton mode: write a text placeholder instead of a real PDF
        path = path.replace(".pdf", ".txt")
        with open(path, "w") as fh:
            fh.write(f"Incident report placeholder for {state.get('source_ip')}\n")
        return path

    c = _canvas.Canvas(path, pagesize=A4)
    w = _Writer(c)

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, w.y, "CyREN Incident Response Report")
    w.y -= 16
    c.setFont("Helvetica", 9)
    c.drawString(50, w.y, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    w.y -= 10

    w.heading("Alert Details")
    w.line("Attack Type", state.get("attack_type"))
    w.line("Detection Rule", state.get("rule"))
    w.line("Source IP", state.get("source_ip"))
    w.line("Destination", state.get("dest_ip"))
    w.line("Severity", state.get("severity"))
    w.line("Aggregated Logs", state.get("log_count"))
    w.line("Risk Tier", state.get("risk"))
    w.line("Classifier Confidence", state.get("confidence"))

    w.heading("AI Analysis")
    summary = state.get("llm_summary") or {}
    w.line("MITRE ATT&CK", ", ".join(state.get("mitre_techniques") or []) or "N/A")
    w.line("What Happened", summary.get("what_happened", "N/A"))
    w.line("Potential Impact", summary.get("what_could_go_wrong", "N/A"))
    w.line("Recommendation", summary.get("what_should_be_done", "N/A"))
    w.line("Urgency", summary.get("urgency", "N/A"))

    w.heading("Context (Enrichment)")
    ti = state.get("threat_intel") or {}
    asset = state.get("asset") or {}
    vuln = state.get("vulnerability") or {}
    w.line("Source Reputation", f"known_bad={ti.get('known_bad')}, score={ti.get('score')}, "
                                f"sources={ti.get('sources')}")
    w.line("Target Asset", f"{asset.get('name', 'unknown')} "
                           f"(criticality: {asset.get('criticality', 'unknown')})")
    w.line("Matching CVEs", vuln.get("matching_cves") or "none known")

    if state.get("is_multistage"):
        w.heading("Attack Chain")
        w.line("Chain Risk", state.get("chain_risk"))
        w.line("Assessment", state.get("chain_assessment"))
        for stage in state.get("chain_stages") or []:
            w.line(stage.get("phase", "?"), f"{stage.get('attack_type')} at {stage.get('timestamp')}")
        w.line("Predicted Next Stage", state.get("predicted_next") or "none")

    w.heading("Response Actions")
    w.line("Action Taken", state.get("action_taken"))
    w.line("Source IP Blocked", state.get("blocked"))

    c.save()
    return path
