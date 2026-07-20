"""
Report service: generates a PDF incident report for an event.

The response agent calls generate_report(state) for high-risk incidents, and
the API calls it on demand for any event. The layout follows the incident
report structure validated in the FYP1 prototype, styled to match the CyREN
dashboard (navy #0d2c50 / yellow #ffd60a):

    header band -> Alert Details -> Threat Classification -> AI Analysis
    -> MITRE ATT&CK -> Attack Chain -> Context -> Raw Logs -> Response Actions

Everything is drawn with reportlab's low-level canvas through the small set of
layout primitives below (section bars, key/value and data tables, paragraph
boxes, code boxes, pills), each of which handles its own page breaks.
"""
import io
import os
import textwrap
from datetime import datetime

from config.settings import settings

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas as _canvas
except ImportError:
    _canvas = None

# ----------------------------------------------------------------- constants
# Stamped into every generated filename. Bump this whenever the layout or the
# content of the report changes: callers compare it against the stored
# file_path and regenerate anything produced by an older version, so reports
# on disk never lag behind the current design.
REPORT_FORMAT_VERSION = "v2"

PAGE_W, PAGE_H = 595, 842          # A4 in points
MARGIN = 45
CONTENT_W = PAGE_W - 2 * MARGIN
HEADER_H = 86
FOOTER_H = 38

NAVY = (0.051, 0.173, 0.314)       # #0d2c50
YELLOW = (1.0, 0.839, 0.039)       # #ffd60a
INK = (0.102, 0.102, 0.102)        # #1a1a1a
MUTED = (0.42, 0.40, 0.35)
RULE = (0.80, 0.78, 0.72)
BAND = (0.96, 0.945, 0.90)         # table zebra / label column
BOX = (0.976, 0.965, 0.925)        # paragraph + code box fill

RISK_COLORS = {                    # fill, text
    "high": ((1.0, 0.322, 0.322), (1, 1, 1)),
    "uncertain": (YELLOW, INK),
    "low": ((0.024, 0.839, 0.627), INK),
}
URGENCY_COLORS = {
    "high": ((1.0, 0.322, 0.322), (1, 1, 1)),
    "critical": ((1.0, 0.322, 0.322), (1, 1, 1)),
    "medium": (YELLOW, INK),
    "low": ((0.024, 0.839, 0.627), INK),
}

# Technique -> tactic. The knowledge base stores techniques as plain strings
# ("T1190 Exploit Public-Facing Application") with no tactic, so the report
# resolves it here; sub-techniques fall back to their parent ID.
MITRE_TACTICS = {
    "T1046": "Discovery",
    "T1059": "Execution",
    "T1005": "Collection",
    "T1078": "Defense Evasion",
    "T1110": "Credential Access",
    "T1190": "Initial Access",
    "T1213": "Collection",
    "T1505": "Persistence",
    "T1566": "Initial Access",
    "T1071": "Command and Control",
}


def _tactic_for(technique_id):
    tid = (technique_id or "").strip()
    return MITRE_TACTICS.get(tid) or MITRE_TACTICS.get(tid.split(".")[0]) or "—"


def _split_technique(entry):
    """"T1110.001 Brute Force: Password Guessing" -> (id, name)."""
    text = str(entry or "").strip()
    if not text:
        return "—", "—"
    parts = text.split(" ", 1)
    if parts[0].upper().startswith("T"):
        return parts[0], (parts[1] if len(parts) > 1 else "—")
    return "—", text


def _fmt_ts(value, fallback="—"):
    if not value:
        return fallback
    return str(value).replace("T", " ")[:19]


def _fmt_conf(value):
    try:
        return f"{float(value) * 100:.0f}%"
    except (TypeError, ValueError):
        return "—"


def _verdict(risk):
    return {"high": "True Positive",
            "low": "Likely False Positive"}.get(risk, "Needs Analyst Review")


# ------------------------------------------------------------------- writer
class _Doc:
    """Layout primitives over a reportlab canvas, with automatic pagination."""

    def __init__(self, c, state, total_pages=None):
        self.c = c
        self.state = state
        self.total_pages = total_pages
        self.page = 1
        self._start_page()

    # -- chrome ----------------------------------------------------------
    def _start_page(self):
        self._draw_header()
        self._draw_footer()
        # page 1 also carries the report title and the meta line under the band
        self.y = PAGE_H - HEADER_H - (52 if self.page == 1 else 16)

    def _draw_header(self):
        c, s = self.c, self.state
        c.setFillColorRGB(*NAVY)
        c.rect(0, PAGE_H - HEADER_H, PAGE_W, HEADER_H, stroke=0, fill=1)

        # logo mark: yellow rounded square with a navy "C"
        c.setFillColorRGB(*YELLOW)
        c.roundRect(MARGIN, PAGE_H - 60, 30, 30, 7, stroke=0, fill=1)
        c.setFillColorRGB(*NAVY)
        c.setFont("Helvetica-Bold", 20)
        c.drawCentredString(MARGIN + 15, PAGE_H - 53, "C")

        c.setFillColorRGB(*YELLOW)
        c.setFont("Helvetica-Bold", 19)
        c.drawString(MARGIN + 40, PAGE_H - 47, "CyREN")
        c.setFillColorRGB(1, 1, 1)
        c.setFont("Helvetica", 7.5)
        c.drawString(MARGIN + 41, PAGE_H - 58, "SOC INCIDENT RESPONSE")

        risk = (s.get("risk") or "").lower()
        fill, text = RISK_COLORS.get(risk, ((0.68, 0.71, 0.74), INK))
        label = f"{(risk or 'unknown').upper()} RISK"
        w = c.stringWidth(label, "Helvetica-Bold", 10) + 22
        c.setFillColorRGB(*fill)
        c.roundRect(PAGE_W - MARGIN - w, PAGE_H - 56, w, 22, 5, stroke=0, fill=1)
        c.setFillColorRGB(*text)
        c.setFont("Helvetica-Bold", 10)
        c.drawCentredString(PAGE_W - MARGIN - w / 2, PAGE_H - 49, label)

        # title strip under the band (first page only)
        if self.page == 1:
            c.setFillColorRGB(*INK)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(MARGIN, PAGE_H - HEADER_H - 22, "Incident Response Report")
            eid = s.get("event_id")
            meta = "  ·  ".join(filter(None, [
                f"Incident #{eid}" if eid else "Incident (not yet persisted)",
                s.get("source_ip") or None,
                "Generated " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + " UTC",
            ]))
            c.setFillColorRGB(*MUTED)
            c.setFont("Helvetica", 8.5)
            c.drawString(MARGIN, PAGE_H - HEADER_H - 34, meta)

    def _draw_footer(self):
        c = self.c
        c.setStrokeColorRGB(*RULE)
        c.setLineWidth(0.8)
        c.line(MARGIN, FOOTER_H + 6, PAGE_W - MARGIN, FOOTER_H + 6)
        c.setFillColorRGB(*MUTED)
        c.setFont("Helvetica", 8)
        c.drawString(MARGIN, FOOTER_H - 6, "CyREN SOC Incident Response")
        label = (f"Page {self.page} of {self.total_pages}"
                 if self.total_pages else f"Page {self.page}")
        c.drawRightString(PAGE_W - MARGIN, FOOTER_H - 6, label)

    def _new_page(self):
        self.c.showPage()
        self.page += 1
        self._start_page()

    def need(self, height):
        """Break to a new page when `height` points would not fit."""
        if self.y - height < FOOTER_H + 20:
            self._new_page()

    def space(self, h=10):
        self.y -= h

    # -- blocks ----------------------------------------------------------
    def section(self, title, keep=0):
        # Reserve room for the bar plus the block that follows it, so a
        # heading never ends up stranded at the foot of a page while its
        # content starts on the next one. `keep` is the caller's estimate of
        # that block's height; it is capped so an oversized block (which will
        # paginate internally anyway) does not force a needless break.
        self.need(min(max(92, 30 + keep), self._usable_height()))
        self.space(6)
        c = self.c
        c.setFillColorRGB(*NAVY)
        c.roundRect(MARGIN, self.y - 17, CONTENT_W, 20, 4, stroke=0, fill=1)
        c.setFillColorRGB(*YELLOW)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(MARGIN + 10, self.y - 11, title.upper())
        self.y -= 30

    def caption(self, text):
        """Small muted line, e.g. above a table or a code box."""
        self.need(16)
        self.c.setFillColorRGB(*MUTED)
        self.c.setFont("Helvetica", 8)
        self.c.drawString(MARGIN, self.y - 8, str(text))
        self.y -= 16

    def _usable_height(self):
        """How much vertical room a block gets on a fresh (non-first) page."""
        return (PAGE_H - HEADER_H - 16) - (FOOTER_H + 20)

    def keep_together(self, height):
        """Move to a new page if `height` does not fit here but would fit
        on a fresh page, so short blocks are not split across pages."""
        if self.y - height < FOOTER_H + 20 and height <= self._usable_height():
            self._new_page()

    @staticmethod
    def _prep_kv(rows):
        prepared = []
        for label, value in rows:
            text = "—" if value in (None, "") else str(value)
            lines = textwrap.wrap(text, width=62) or ["—"]
            prepared.append((label, lines, max(18, 4 + len(lines) * 12)))
        return prepared

    def kv_height(self, rows):
        """Height a kv_table will occupy, for section() to reserve up front."""
        return sum(h for _, _, h in self._prep_kv(rows)) + 4

    def kv_table(self, rows, label_w=150):
        """Two-column label/value table with a shaded label column."""
        c = self.c
        prepared = self._prep_kv(rows)
        self.keep_together(sum(h for _, _, h in prepared) + 4)

        for i, (label, lines, h) in enumerate(prepared):
            self.need(h + 4)
            top = self.y

            c.setFillColorRGB(*BAND)
            c.rect(MARGIN, top - h, label_w, h, stroke=0, fill=1)
            if i % 2 == 1:
                c.setFillColorRGB(0.988, 0.982, 0.965)
                c.rect(MARGIN + label_w, top - h, CONTENT_W - label_w, h, stroke=0, fill=1)

            c.setStrokeColorRGB(*RULE)
            c.setLineWidth(0.6)
            c.rect(MARGIN, top - h, CONTENT_W, h, stroke=1, fill=0)
            c.line(MARGIN + label_w, top - h, MARGIN + label_w, top)

            c.setFillColorRGB(*INK)
            c.setFont("Helvetica-Bold", 8.5)
            c.drawString(MARGIN + 8, top - 13, str(label))
            c.setFont("Helvetica", 8.5)
            for j, line in enumerate(lines):
                c.drawString(MARGIN + label_w + 8, top - 13 - j * 12, line)
            self.y = top - h

    def data_table(self, headers, rows, widths):
        """Multi-column table with a navy header row."""
        c = self.c
        # rough height estimate so a short table is not split across pages
        self.keep_together(17 + max(len(rows), 1) * 18 + 4)
        self.need(34)
        c.setFillColorRGB(*NAVY)
        c.rect(MARGIN, self.y - 17, CONTENT_W, 17, stroke=0, fill=1)
        c.setFillColorRGB(*YELLOW)
        c.setFont("Helvetica-Bold", 8)
        x = MARGIN
        for head, w in zip(headers, widths):
            c.drawString(x + 7, self.y - 12, str(head).upper())
            x += w
        self.y -= 17

        if not rows:
            self.need(20)
            c.setFillColorRGB(*MUTED)
            c.setFont("Helvetica-Oblique", 8.5)
            c.drawString(MARGIN + 7, self.y - 13, "None recorded.")
            self.y -= 20
            return

        for i, row in enumerate(rows):
            wrapped = []
            for cell, w in zip(row, widths):
                chars = max(8, int((w - 14) / 4.4))
                wrapped.append(textwrap.wrap(str(cell if cell not in (None, "") else "—"),
                                             width=chars) or ["—"])
            h = max(17, 5 + max(len(col) for col in wrapped) * 11)
            self.need(h + 2)
            top = self.y

            if i % 2 == 1:
                c.setFillColorRGB(*BAND)
                c.rect(MARGIN, top - h, CONTENT_W, h, stroke=0, fill=1)
            c.setStrokeColorRGB(*RULE)
            c.setLineWidth(0.6)
            c.rect(MARGIN, top - h, CONTENT_W, h, stroke=1, fill=0)

            c.setFillColorRGB(*INK)
            x = MARGIN
            for col, w in zip(wrapped, widths):
                if x > MARGIN:
                    c.line(x, top - h, x, top)
                c.setFont("Helvetica", 8)
                for j, line in enumerate(col):
                    c.drawString(x + 7, top - 12 - j * 11, line)
                x += w
            self.y = top - h

    def para_box(self, title, text, pill=None):
        """Tinted box with a small heading and a wrapped paragraph."""
        c = self.c
        body = str(text).strip() if text not in (None, "") else "Not available."
        lines = textwrap.wrap(body, width=97) or ["Not available."]
        h = 26 + len(lines) * 11
        self.need(h + 6)
        top = self.y

        c.setFillColorRGB(*BOX)
        c.roundRect(MARGIN, top - h, CONTENT_W, h, 4, stroke=0, fill=1)
        c.setStrokeColorRGB(*RULE)
        c.setLineWidth(0.7)
        c.roundRect(MARGIN, top - h, CONTENT_W, h, 4, stroke=1, fill=0)

        c.setFillColorRGB(*NAVY)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(MARGIN + 10, top - 15, title)
        if pill:
            self._pill(PAGE_W - MARGIN - 10, top - 17, *pill)

        c.setFillColorRGB(*INK)
        c.setFont("Helvetica", 8.5)
        for j, line in enumerate(lines):
            c.drawString(MARGIN + 10, top - 28 - j * 11, line)
        self.y = top - h - 6

    def _pill(self, right_x, y, label, fill, text_color):
        c = self.c
        w = c.stringWidth(label, "Helvetica-Bold", 7.5) + 16
        c.setFillColorRGB(*fill)
        c.roundRect(right_x - w, y, w, 14, 4, stroke=0, fill=1)
        c.setFillColorRGB(*text_color)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawCentredString(right_x - w / 2, y + 4, label)

    def confidence_bar(self, confidence, risk):
        """Big percentage + a filled progress bar tinted by risk tier."""
        c = self.c
        self.need(56)
        top = self.y
        try:
            frac = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            frac = 0.0
        fill, _ = RISK_COLORS.get((risk or "").lower(), ((0.68, 0.71, 0.74), INK))

        c.setFillColorRGB(*INK)
        c.setFont("Helvetica-Bold", 22)
        c.drawString(MARGIN, top - 22, _fmt_conf(confidence))
        c.setFont("Helvetica", 9)
        c.setFillColorRGB(*MUTED)
        c.drawString(MARGIN + 78, top - 14, "Classifier confidence")
        c.setFillColorRGB(*INK)
        c.setFont("Helvetica-Bold", 9.5)
        c.drawString(MARGIN + 78, top - 26, _verdict((risk or "").lower()))

        bar_y = top - 44
        c.setFillColorRGB(1, 1, 1)
        c.rect(MARGIN, bar_y, CONTENT_W, 12, stroke=0, fill=1)
        c.setFillColorRGB(*fill)
        if frac > 0:
            c.rect(MARGIN, bar_y, CONTENT_W * frac, 12, stroke=0, fill=1)
        c.setStrokeColorRGB(*INK)
        c.setLineWidth(1)
        c.rect(MARGIN, bar_y, CONTENT_W, 12, stroke=1, fill=0)

        # same sentence the dashboard shows under the confidence bar
        note = (f"The XGBoost classifier scored this event at {_fmt_conf(confidence)} "
                f"confidence, which falls in the \"{risk or 'unknown'}\" tier.")
        c.setFillColorRGB(*MUTED)
        c.setFont("Helvetica", 8)
        c.drawString(MARGIN, bar_y - 14, note)
        self.y = bar_y - 26

    def code_box(self, lines, max_lines=12):
        """Monospace sample on a tinted background."""
        c = self.c
        shown = [str(x) for x in (lines or [])][:max_lines]
        extra = max(0, len(lines or []) - len(shown))
        if not shown:
            shown = ["No raw log sample stored for this event."]

        rows = [ln if len(ln) <= 104 else ln[:101] + "..." for ln in shown]
        h = 14 + len(rows) * 10.5 + (12 if extra else 0)
        self.keep_together(h + 6)
        self.need(h + 6)
        top = self.y

        c.setFillColorRGB(*BOX)
        c.rect(MARGIN, top - h, CONTENT_W, h, stroke=0, fill=1)
        c.setStrokeColorRGB(*RULE)
        c.setLineWidth(0.7)
        c.rect(MARGIN, top - h, CONTENT_W, h, stroke=1, fill=0)

        c.setFillColorRGB(*INK)
        c.setFont("Courier", 7.2)
        for j, line in enumerate(rows):
            c.drawString(MARGIN + 8, top - 16 - j * 10.5, line)
        if extra:
            c.setFillColorRGB(*MUTED)
            c.setFont("Helvetica-Oblique", 7.5)
            c.drawString(MARGIN + 8, top - 16 - len(rows) * 10.5, f"... and {extra} more log lines")
        self.y = top - h - 4


# ------------------------------------------------------------------ content
def _render(c, state, total_pages=None):
    d = _Doc(c, state, total_pages)

    # 1. Alert details -----------------------------------------------------
    alert_rows = [
        ("Event ID", f"#{state['event_id']}" if state.get("event_id") else "pending"),
        ("Attack Type", state.get("attack_type")),
        ("Detection Rule", state.get("rule")),
        ("Source IP", state.get("source_ip")),
        ("Destination IP", state.get("dest_ip")),
        ("Aggregated Logs", state.get("log_count")),
        ("First Seen", _fmt_ts(state.get("first_seen"))),
        ("Last Seen", _fmt_ts(state.get("last_seen"))),
    ]
    d.section("Alert Details", keep=d.kv_height(alert_rows))
    d.kv_table(alert_rows)

    # 2. Classification ----------------------------------------------------
    d.section("Threat Classification (XGBoost)", keep=70)
    d.confidence_bar(state.get("confidence"), state.get("risk"))

    # 3. AI analysis -------------------------------------------------------
    d.section("AI Analysis")
    summary = state.get("llm_summary") or {}
    urgency = str(summary.get("urgency") or "").strip()
    d.para_box("What Happened", summary.get("what_happened"))
    d.para_box("Potential Impact", summary.get("what_could_go_wrong"))
    d.para_box("Recommended Action", summary.get("what_should_be_done"))
    if urgency:
        fill, text = URGENCY_COLORS.get(urgency.lower(), (BAND, INK))
        d.para_box("Urgency", f"The analysis rates the urgency of this incident as {urgency}.",
                   pill=(urgency.upper(), fill, text))

    # 4. MITRE -------------------------------------------------------------
    rows = []
    for entry in state.get("mitre_techniques") or []:
        tid, name = _split_technique(entry)
        rows.append((tid, name, _tactic_for(tid)))
    d.section("MITRE ATT&CK Techniques", keep=17 + max(len(rows), 1) * 18 + 4)
    d.data_table(["Technique ID", "Technique", "Tactic"], rows, [95, 260, 150])

    # 5. Attack chain ------------------------------------------------------
    if state.get("is_multistage") or state.get("chain_stages"):
        d.section("Attack Chain", keep=64)
        chain_risk = str(state.get("chain_risk") or "").lower()
        fill, text = RISK_COLORS.get(
            {"critical": "high", "medium": "uncertain"}.get(chain_risk, chain_risk),
            (BAND, INK))
        d.para_box("Chain Assessment",
                   state.get("chain_assessment") or "Multiple related stages observed.",
                   pill=((state.get("chain_risk") or "?").upper(), fill, text))
        stages = []
        for i, stage in enumerate(state.get("chain_stages") or [], start=1):
            stages.append((i, stage.get("phase"), stage.get("attack_type"),
                           _fmt_ts(stage.get("timestamp"))))
        d.data_table(["#", "Kill Chain Phase", "Attack Type", "Timestamp"],
                     stages, [30, 165, 165, 145])
        if state.get("predicted_next"):
            d.space(4)
            d.para_box("Predicted Next Stage",
                       f"Based on the observed progression, the next stage to watch for is "
                       f"{state['predicted_next']}.")

    # 6. Enrichment --------------------------------------------------------
    ti = state.get("threat_intel") or {}
    asset = state.get("asset") or {}
    vuln = state.get("vulnerability") or {}
    cves = vuln.get("matching_cves")
    if isinstance(cves, (list, tuple)):
        cves = ", ".join(str(x) for x in cves)
    context_rows = [
        ("Source Reputation",
         f"known bad: {ti.get('known_bad', 'unknown')}  |  score: {ti.get('score', 'n/a')}"
         f"  |  sources: {ti.get('sources') or 'none'}"),
        ("Target Asset",
         f"{asset.get('name', 'unknown')} (criticality: {asset.get('criticality', 'unknown')})"),
        ("Matching CVEs", cves or "None known"),
    ]
    d.section("Context & Enrichment", keep=d.kv_height(context_rows))
    d.kv_table(context_rows)

    # 7. Raw logs ----------------------------------------------------------
    sample = state.get("raw_log_sample") or state.get("raw_logs") or []
    d.section("Raw Log Sample", keep=16 + 14 + min(len(sample) or 1, 12) * 11)
    if sample:
        d.caption(f"Showing {min(len(sample), 12)} of {state.get('log_count') or len(sample)} "
                  f"aggregated log lines.")
    d.code_box(sample)

    # 8. Response ----------------------------------------------------------
    action = state.get("action_taken")
    ip = state.get("source_ip") or "the source address"
    if action == "blocked":
        note = f"IP blocked. A firewall rule is dropping all traffic from {ip}."
    elif action == "awaiting_approval":
        note = "Waiting for an analyst decision. Nothing has been blocked yet."
    elif action and action.startswith("dismissed"):
        note = "Dismissed as a false positive by an analyst."
    else:
        note = "Logged. The system judged this low risk; no blocking action was taken."

    if state.get("decided_by"):
        approver = f"{state['decided_by']} (analyst decision)"
    elif state.get("blocked_by") == "auto" or action == "blocked":
        approver = "Automatic (policy: high risk auto-block)"
    else:
        approver = "No analyst decision recorded"

    response_rows = [
        ("Action Taken", str(action or "logged").replace("_", " ")),
        ("Source IP Blocked", "Yes" if state.get("blocked") else "No"),
        ("Blocked At", _fmt_ts(state.get("blocked_at"), "—")),
        ("Decided By", approver),
        ("Decision Time", _fmt_ts(state.get("decided_at"), "—")),
        ("Notification", "Email sent to the SOC team" if action == "blocked" else "Not sent"),
    ]
    d.section("Response Actions", keep=16 + d.kv_height(response_rows))
    d.caption(note)
    d.kv_table(response_rows)


def generate_report(state: dict) -> str:
    os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
    filename = (f"CyREN_Incident_{state.get('source_ip','unknown')}_{ts}"
                f"_{REPORT_FORMAT_VERSION}.pdf")
    path = os.path.join(settings.REPORT_OUTPUT_DIR, filename)

    if _canvas is None:
        # skeleton mode: write a text placeholder instead of a real PDF
        path = path.replace(".pdf", ".txt")
        with open(path, "w") as fh:
            fh.write(f"Incident report placeholder for {state.get('source_ip')}\n")
        return path

    # First pass into a throwaway buffer purely to learn the page count, so
    # the real pass can print "Page N of M" in the footer.
    probe = _canvas.Canvas(io.BytesIO(), pagesize=A4)
    _render(probe, state)
    total = probe.getPageNumber()

    c = _canvas.Canvas(path, pagesize=A4)
    c.setTitle(f"CyREN Incident Report - {state.get('source_ip', 'unknown')}")
    c.setAuthor("CyREN SOC Incident Response")
    _render(c, state, total_pages=total)
    c.save()
    return path
