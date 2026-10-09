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
from datetime import datetime, timezone

from config.settings import settings

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas as _canvas
    from reportlab.pdfbase.pdfmetrics import stringWidth as _sw
    from reportlab.lib.utils import ImageReader as _ImageReader
except ImportError:
    _canvas = None
    _sw = None


def _wrap(text, max_w, font="Helvetica", size=11):
    """Greedy word wrap by MEASURED width, so a line fills its cell instead of
    breaking at a guessed character count. Over-long words are split."""
    text = "" if text is None else str(text)
    if _sw is None:
        return textwrap.wrap(text, width=60) or [""]
    out, line = [], ""
    for word in text.split():
        cand = (line + " " + word) if line else word
        if _sw(cand, font, size) <= max_w:
            line = cand
            continue
        if line:
            out.append(line)
        # a single word wider than the cell: cut it
        while _sw(word, font, size) > max_w:
            k = len(word)
            while k > 1 and _sw(word[:k], font, size) > max_w:
                k -= 1
            out.append(word[:k]); word = word[k:]
        line = word
    if line:
        out.append(line)
    return out or [""]

# ----------------------------------------------------------------- constants
# Stamped into every generated filename. Bump this whenever the layout or the
# content of the report changes: callers compare it against the stored
# file_path and regenerate anything produced by an older version, so reports
# on disk never lag behind the current design.
REPORT_FORMAT_VERSION = "v35"  # v35: no "Showing the first N of M" caption above the raw log box; v34: unknown target shown as Unknown + resolved IP; v33: asset description column; v32: asset names by site; v31: comments as a table; v30: analyst comment thread with images; v29: dated analyst summaries; v28: discussion, notes, target asset in Alert Details; v27: no log-count caption; v26: 12-hour clock, first/last seen split; v25: user-chosen section order; v24: activity order, audit labels in words; v23: wide tables may shrink to 8 pt; v22: date/time split, local time, no stranded headings; v21: ticket description as a row; v20: self-sizing columns, no count captions; v19: response rows split; v18: ticket rows split, no caption; v17: response table in plain words; v16: no reputation row; v15: no response caption, whitelisted wording, log dividers; v14: reputation in words; v13: measured wrapping, chain order; v12: chain as one block, terminal log box; v11: header dividers; v10: AI Analysis as a table; v9: boxed confidence block; v8: no card frame, darker grid; v7: square bar corners; v6: bar flush on its content; v5: larger type; v4: logo header; v3: Case Ticket

PAGE_W, PAGE_H = 595, 842          # A4 in points
MARGIN = 45
CONTENT_W = PAGE_W - 2 * MARGIN
HEADER_H = 86
FOOTER_H = 38
# the logo files shipped with the web app (white-on-transparent variants for the navy band)
_IMG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static", "img")
LOGO_MARK = os.path.join(_IMG_DIR, "cyren-mark-light.png")
LOGO_TEXT = os.path.join(_IMG_DIR, "cyren-text-light.png")

NAVY = (0.051, 0.173, 0.314)       # #0d2c50
YELLOW = (1.0, 0.839, 0.039)       # #ffd60a
INK = (0.102, 0.102, 0.102)        # #1a1a1a
MUTED = (0.42, 0.40, 0.35)
RULE = (0.55, 0.53, 0.47)          # table grid (darker, so rows read clearly)
BAND = (0.96, 0.945, 0.90)         # table zebra / label column
BOX = (0.976, 0.965, 0.925)        # paragraph + code box fill
CARD_LINE = (0.62, 0.60, 0.55)     # section-card frame border (a touch darker than RULE)

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


def _local_dt(value):
    """Stored UTC timestamp -> ('24-09-2026', '09:54:40') in the server's local
    zone, the same clock the web pages show. ('', '') when there is none."""
    if not value:
        return "", ""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", ""))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        loc = dt.astimezone()
        return loc.strftime("%d-%m-%Y"), loc.strftime("%I:%M:%S %p").lstrip("0")
    except (TypeError, ValueError):
        return str(value), ""


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
        # each section is drawn inside a light "card" frame so it is obvious
        # which heading owns which content — these track the open card
        self._sec_open = False
        self._sec_top = None
        self._start_page()

    def _close_section(self, bottom=None):
        """Draw the frame around the currently-open section card."""
        if not self._sec_open or self._sec_top is None:
            return
        c = self.c
        # the outer rounded frame was dropped: the navy bar plus the table's own
        # grid mark the section clearly enough, and the page reads cleaner
        self._sec_open = False
        self._sec_top = None

    # -- chrome ----------------------------------------------------------
    def _start_page(self):
        self._title_h = 0
        self._draw_header()
        self._draw_footer()
        # page 1 also carries the report title and the info block under the band
        self.y = PAGE_H - HEADER_H - ((self._title_h + 10) if self.page == 1 else 22)
        self._page_top = self.y     # first card on a page sits here, no extra gap

    def _draw_header(self):
        c, s = self.c, self.state
        c.setFillColorRGB(*NAVY)
        c.rect(0, PAGE_H - HEADER_H, PAGE_W, HEADER_H, stroke=0, fill=1)

        # the CyREN logo: cat mark + wordmark, the same files the web app uses
        if os.path.exists(LOGO_MARK) and os.path.exists(LOGO_TEXT):
            c.drawImage(LOGO_MARK, MARGIN, PAGE_H - 64, width=40, height=40, mask="auto")
            c.drawImage(LOGO_TEXT, MARGIN + 48, PAGE_H - 54, width=110, height=17, mask="auto")
        else:   # files missing: plain wordmark so the report still renders
            c.setFillColorRGB(1, 1, 1)
            c.setFont("Helvetica-Bold", 19)
            c.drawString(MARGIN, PAGE_H - 50, "CyREN")

        if not s.get("hide_risk_badge"):
            risk = (s.get("risk") or "").lower()
            fill, text = RISK_COLORS.get(risk, ((0.68, 0.71, 0.74), INK))
            label = f"{(risk or 'unknown').upper()} RISK"
            w = c.stringWidth(label, "Helvetica-Bold", 10) + 22
            c.setFillColorRGB(*fill)
            c.roundRect(PAGE_W - MARGIN - w, PAGE_H - 56, w, 22, 5, stroke=0, fill=1)
            c.setFillColorRGB(*text)
            c.setFont("Helvetica-Bold", 10)
            c.drawCentredString(PAGE_W - MARGIN - w / 2, PAGE_H - 49, label)

        # title and info block under the band (first page only)
        if self.page == 1:
            c.setFillColorRGB(*INK)
            c.setFont("Helvetica-Bold", 20)
            c.drawString(MARGIN, PAGE_H - HEADER_H - 40,
                         s.get("report_title") or "Incident Response Report")
            # who / when, one fact per line: easier to read than one long meta line
            eid = s.get("event_id")
            rows = []
            if s.get("report_ref"):
                rows.append(("Reference", s["report_ref"]))
            elif eid:
                rows.append(("Incident", f"#{eid}"))
            if s.get("source_ip"):
                rows.append(("Source IP", s["source_ip"]))
            if s.get("period"):
                rows.append(("Period", s["period"]))
            now = datetime.now().astimezone()
            rows += [("Generated by", s.get("generated_by") or "CyREN (auto)"),
                     ("Date", now.strftime("%d-%m-%Y")),
                     ("Time", now.strftime("%I:%M:%S %p").lstrip("0"))]
            y = PAGE_H - HEADER_H - 68
            for label, value in rows:
                c.setFillColorRGB(*MUTED)
                c.setFont("Helvetica-Bold", 11)
                c.drawString(MARGIN, y, label)
                c.setFillColorRGB(*INK)
                c.setFont("Helvetica", 11)
                c.drawString(MARGIN + 96, y, str(value))
                y -= 22
            c.setStrokeColorRGB(*RULE)
            c.setLineWidth(0.6)
            c.line(MARGIN, y + 4, PAGE_W - MARGIN, y + 4)
            self._title_h = (PAGE_H - HEADER_H) - (y + 4)

    def _draw_footer(self):
        c = self.c
        c.setStrokeColorRGB(*RULE)
        c.setLineWidth(0.8)
        c.line(MARGIN, FOOTER_H + 6, PAGE_W - MARGIN, FOOTER_H + 6)
        c.setFillColorRGB(*MUTED)
        c.setFont("Helvetica", 9)
        c.drawString(MARGIN, FOOTER_H - 6,
                     "CyREN  ·  " + (self.state.get("report_title") or "Incident Response Report"))
        label = (f"Page {self.page} of {self.total_pages}"
                 if self.total_pages else f"Page {self.page}")
        c.drawRightString(PAGE_W - MARGIN, FOOTER_H - 6, label)

    def _new_page(self):
        # if a section card is open, close it at the bottom of THIS page and
        # reopen it at the top of the next, so a section spanning pages gets a
        # framed segment on each
        cont = self._sec_open
        if cont:
            self._close_section(bottom=FOOTER_H + 12)
        self.c.showPage()
        self.page += 1
        self._start_page()
        if cont:
            self._sec_top = self.y + 6
            self._sec_open = True

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
        # close the previous section's card, THEN check for a page break, so a
        # break happens with no card open (the new card starts cleanly)
        self._close_section()
        # callers estimate `keep` with the old, tighter metrics; scale it to the
        # current line heights and never start a card with less than ~150pt left,
        # so a heading is not stranded above an empty frame at the page foot
        # a block taller than a page paginates anyway, so it only needs room for
        # its heading plus a few rows; a shorter block must fit whole
        want = max(170, 46 + int(keep))
        self.need(want if want <= self._usable_height() else 170)
        # clear breathing room between one card and the next — but not at the
        # very top of a fresh page, where the page header already gives the gap
        self.space(6 if self.y >= self._page_top - 1 else 36)
        c = self.c
        # the card frame will enclose from the top of this header down to the
        # bottom of the section's content
        self._sec_top = self.y + 6
        self._sec_open = True
        c.setFillColorRGB(*NAVY)
        c.roundRect(MARGIN, self.y - 23, CONTENT_W, 28, 4, stroke=0, fill=1)
        # square off the bottom corners so the bar meets the table edge to edge
        c.rect(MARGIN, self.y - 23, CONTENT_W, 10, stroke=0, fill=1)
        c.setFillColorRGB(*YELLOW)
        c.setFont("Helvetica-Bold", 13)
        c.drawString(MARGIN + 10, self.y - 14, title.upper())
        self.y -= 23   # the content (table / box) starts flush under the bar

    def caption(self, text):
        """Small muted line, e.g. above a table or a code box."""
        self.need(30)
        self.c.setFillColorRGB(*MUTED)
        self.c.setFont("Helvetica", 10.5)
        self.c.drawString(MARGIN, self.y - 19, str(text))
        self.y -= 30

    def _usable_height(self):
        """How much vertical room a block gets on a fresh (non-first) page."""
        return (PAGE_H - HEADER_H - 16) - (FOOTER_H + 20)

    def keep_together(self, height):
        """Move to a new page if `height` does not fit here but would fit
        on a fresh page, so short blocks are not split across pages."""
        if self._sec_top is not None and self.y >= self._sec_top - 30:
            return          # directly under its section bar: stay, paginate row by row
        if self.y - height < FOOTER_H + 20 and height <= self._usable_height():
            self._new_page()

    @staticmethod
    def _prep_kv(rows, label_w=150):
        prepared = []
        for label, value in rows:
            text = "—" if value in (None, "") else str(value)
            lines = _wrap(text, CONTENT_W - label_w - 16, "Helvetica", 11)
            prepared.append((label, lines, max(30, 11 + len(lines) * 17)))
        return prepared

    def kv_height(self, rows, label_w=150):
        """Height a kv_table will occupy, for section() to reserve up front."""
        return sum(h for _, _, h in self._prep_kv(rows, label_w)) + 4

    def kv_table(self, rows, label_w=150, gap=8):
        """Two-column label/value table with a shaded label column."""
        c = self.c
        prepared = self._prep_kv(rows, label_w)
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
            c.setLineWidth(1.0)
            c.rect(MARGIN, top - h, CONTENT_W, h, stroke=1, fill=0)
            c.line(MARGIN + label_w, top - h, MARGIN + label_w, top)

            c.setFillColorRGB(*INK)
            c.setFont("Helvetica-Bold", 11)
            c.drawString(MARGIN + 8, top - 19.5, str(label))
            c.setFont("Helvetica", 11)
            for j, line in enumerate(lines):
                c.drawString(MARGIN + label_w + 8, top - 19.5 - j * 17, line)
            self.y = top - h
        self.y -= gap

    @staticmethod
    def _fit_columns(headers, rows, widths):
        """Pick the largest font (11 -> 9) at which every cell fits its column
        on one line, and give each column the room its content needs, with the
        left-over width shared out in the proportions the caller asked for.
        Returns (font_size, widths)."""
        if _sw is None:
            return 11, list(widths)
        n = len(headers)
        base = [float(w) for w in widths]
        scale = CONTENT_W / sum(base)
        base = [w * scale for w in base]
        for size in (11, 10.5, 10, 9.5, 9, 8.5, 8):   # wide tables (9 columns) may need 8 pt
            need = []
            for i in range(n):
                hw = _sw(str(headers[i]).upper(), "Helvetica-Bold", size - 0.5) + 16
                cw = max([_sw("—" if r[i] in (None, "") else str(r[i]), "Helvetica", size)
                          for r in rows] or [0]) + 14
                need.append(max(hw, cw))
            total = sum(need)
            if total <= CONTENT_W:
                extra = CONTENT_W - total
                share = sum(base)
                return size, [need[i] + extra * base[i] / share for i in range(n)]
        # nothing fits on one line even at 8 pt: keep the caller's proportions and wrap
        return 8, base

    def data_table(self, headers, rows, widths, gap=8):
        """Multi-column table with a navy header row."""
        c = self.c
        size, widths = self._fit_columns(headers, rows, widths)
        lh = round(size * 1.55, 1)           # line height for this font size
        row_min = 30 if size >= 10 else (26 if size >= 9 else 23)
        # rough height estimate so a short table is not split across pages
        self.keep_together(27 + max(len(rows), 1) * row_min + 8)
        self.need(58)
        c.setFillColorRGB(*NAVY)
        c.rect(MARGIN, self.y - 27, CONTENT_W, 27, stroke=0, fill=1)
        # column dividers and a top rule in a lighter blue, so the header row
        # reads as a row of cells and does not melt into the section bar above
        c.setStrokeColorRGB(0.45, 0.56, 0.72)
        c.setLineWidth(0.8)
        c.line(MARGIN, self.y, MARGIN + CONTENT_W, self.y)
        x = MARGIN
        for w in widths[:-1]:
            x += w
            c.line(x, self.y - 27, x, self.y)
        c.setFillColorRGB(*YELLOW)
        c.setFont("Helvetica-Bold", size - 0.5)
        x = MARGIN
        for head, w in zip(headers, widths):
            c.drawCentredString(x + w / 2, self.y - 18, str(head).upper())
            x += w
        self.y -= 27

        if not rows:
            self.need(30)
            c.setFillColorRGB(*MUTED)
            c.setFont("Helvetica-Oblique", size)
            c.drawString(MARGIN + 7, self.y - 19.5, "None recorded.")
            self.y -= 30
            return

        for i, row in enumerate(rows):
            wrapped = []
            for cell, w in zip(row, widths):
                wrapped.append(_wrap("—" if cell in (None, "") else cell, w - 14, "Helvetica", size))
            h = max(row_min, 13 + max(len(col) for col in wrapped) * lh)
            self.need(h + 2)
            top = self.y

            if i % 2 == 1:
                c.setFillColorRGB(*BAND)
                c.rect(MARGIN, top - h, CONTENT_W, h, stroke=0, fill=1)
            c.setStrokeColorRGB(*RULE)
            c.setLineWidth(1.0)
            c.rect(MARGIN, top - h, CONTENT_W, h, stroke=1, fill=0)

            c.setFillColorRGB(*INK)
            x = MARGIN
            for col, w in zip(wrapped, widths):
                if x > MARGIN:
                    c.line(x, top - h, x, top)
                c.setFont("Helvetica", size)
                for j, line in enumerate(col):
                    c.drawString(x + 7, top - (row_min - 10.5) - j * lh, line)
                x += w
            self.y = top - h
        self.y -= gap

    def note_block(self, note, attachment_only=False):
        """One analyst comment: a tinted box with 'date time · by', the text,
        and the attached image (scaled to the box) when there is one. With
        attachment_only the text is left out (it is already in the table)."""
        c = self.c
        dd, tt = _local_dt(note.get("created_at"))
        head = " \u00b7 ".join(x for x in (dd, tt, note.get("by") or "") if x)
        if note.get("edited"):
            head += "  (edited)"
        if attachment_only:
            head = "Attachment \u00b7 " + head
        lines = [] if attachment_only else _wrap(note.get("text") or "", CONTENT_W - 20, "Helvetica", 11)
        img, iw, ih = None, 0, 0
        if note.get("image") and _ImageReader is not None:
            try:
                img = _ImageReader(note["image"])
                w0, h0 = img.getSize()
                iw = min(CONTENT_W - 20, float(w0))
                ih = iw * float(h0) / float(w0)
                if ih > 300:                     # keep a very tall picture within a page
                    ih, iw = 300.0, 300.0 * float(w0) / float(h0)
            except Exception:
                img = None
        h = 34 + len(lines) * 17 + (ih + 12 if img else 0)
        self.need(min(h + 6, self._usable_height()))
        if self._sec_top is not None and self.y >= self._sec_top - 30:
            self.y -= 8
        top = self.y
        c.setFillColorRGB(*BOX)
        c.roundRect(MARGIN, top - h, CONTENT_W, h, 4, stroke=0, fill=1)
        c.setStrokeColorRGB(*RULE)
        c.setLineWidth(0.7)
        c.roundRect(MARGIN, top - h, CONTENT_W, h, 4, stroke=1, fill=0)
        c.setFillColorRGB(*NAVY)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN + 10, top - 18, head)
        c.setFillColorRGB(*INK)
        c.setFont("Helvetica", 11)
        y = top - 36
        for line in lines:
            c.drawString(MARGIN + 10, y, line)
            y -= 17
        if img:
            c.drawImage(img, MARGIN + 10, y - ih + 8, width=iw, height=ih, mask="auto")
        self.y = top - h - 10

    def para_box(self, title, text, pill=None):
        """Tinted box with a small heading and a wrapped paragraph."""
        c = self.c
        body = str(text).strip() if text not in (None, "") else "Not available."
        lines = _wrap(body, CONTENT_W - 20, "Helvetica", 11)
        h = 40 + len(lines) * 17
        self.need(h + 6)
        if self._sec_top is not None and self.y >= self._sec_top - 30:
            self.y -= 8          # first box right under the section bar
        top = self.y

        c.setFillColorRGB(*BOX)
        c.roundRect(MARGIN, top - h, CONTENT_W, h, 4, stroke=0, fill=1)
        c.setStrokeColorRGB(*RULE)
        c.setLineWidth(0.7)
        c.roundRect(MARGIN, top - h, CONTENT_W, h, 4, stroke=1, fill=0)

        c.setFillColorRGB(*NAVY)
        c.setFont("Helvetica-Bold", 13)
        c.drawString(MARGIN + 10, top - 20, title)
        if pill:
            self._pill(PAGE_W - MARGIN - 10, top - 22, *pill)

        c.setFillColorRGB(*INK)
        c.setFont("Helvetica", 11)
        for j, line in enumerate(lines):
            c.drawString(MARGIN + 10, top - 40 - j * 17, line)
        self.y = top - h - 12

    def _pill(self, right_x, y, label, fill, text_color):
        c = self.c
        w = c.stringWidth(label, "Helvetica-Bold", 10.5) + 18
        c.setFillColorRGB(*fill)
        c.roundRect(right_x - w, y, w, 14, 4, stroke=0, fill=1)
        c.setFillColorRGB(*text_color)
        c.setFont("Helvetica-Bold", 10.5)
        c.drawCentredString(right_x - w / 2, y + 4, label)

    def confidence_bar(self, confidence, risk):
        """Big percentage + a filled progress bar tinted by risk tier, inside a
        bordered box that sits flush under the section bar like a table."""
        c = self.c
        PAD = 12                                   # inset of the content inside the box
        self.need(96)
        box_top = self.y
        top = box_top - PAD
        x0 = MARGIN + PAD
        inner_w = CONTENT_W - 2 * PAD
        try:
            frac = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            frac = 0.0
        fill, _ = RISK_COLORS.get((risk or "").lower(), ((0.68, 0.71, 0.74), INK))

        c.setFillColorRGB(*INK)
        c.setFont("Helvetica-Bold", 26)
        c.drawString(x0, top - 24, _fmt_conf(confidence))
        c.setFont("Helvetica", 11)
        c.setFillColorRGB(*MUTED)
        c.drawString(x0 + 92, top - 13, "Classifier confidence")
        c.setFillColorRGB(*INK)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(x0 + 92, top - 29, _verdict((risk or "").lower()))

        bar_y = top - 50
        c.setFillColorRGB(1, 1, 1)
        c.rect(x0, bar_y, inner_w, 12, stroke=0, fill=1)
        c.setFillColorRGB(*fill)
        if frac > 0:
            c.rect(x0, bar_y, inner_w * frac, 12, stroke=0, fill=1)
        c.setStrokeColorRGB(*INK)
        c.setLineWidth(1)
        c.rect(x0, bar_y, inner_w, 12, stroke=1, fill=0)

        # same sentence the dashboard shows under the confidence bar
        note = (f"The XGBoost classifier scored this event at {_fmt_conf(confidence)} "
                f"confidence, which falls in the \"{risk or 'unknown'}\" tier.")
        c.setFillColorRGB(*MUTED)
        c.setFont("Helvetica", 10.5)
        c.drawString(x0, bar_y - 18, note)

        # the box: same grid colour and weight as the tables
        box_bot = bar_y - 18 - PAD
        c.setStrokeColorRGB(*RULE)
        c.setLineWidth(1.0)
        c.rect(MARGIN, box_bot, CONTENT_W, box_top - box_bot, stroke=1, fill=0)
        self.y = box_bot - 8

    def code_box(self, lines, max_lines=None):
        """Monospace log sample on a tinted background. Shows EVERY line in
        full — long lines wrap instead of being cut — with a little spacing
        between entries, and the box paginates across pages when long."""
        c = self.c
        items = [str(x) for x in (lines or [])]
        if not items:
            items = ["No raw log sample stored for this event."]
        # wrap each log line so nothing is truncated (Courier 7.2pt ≈ 4.32pt/char)
        entries = [textwrap.wrap(ln, width=88, break_long_words=True) or [""]
                   for ln in items]

        LINE_H = 13.5
        GAP = 10.0          # spacing between consecutive log lines
        PAD = 8.0
        i, n = 0, len(entries)
        while i < n:
            self.need(28)
            box_top = self.y
            avail = self.y - (FOOTER_H + 20)
            used = PAD
            page_entries = []
            while i < n:
                eh = len(entries[i]) * LINE_H + GAP
                if page_entries and used + eh + PAD > avail:
                    break            # full — close this box, continue on next page
                page_entries.append(entries[i])
                used += eh
                i += 1
            box_h = used + PAD - GAP
            # same look as the Raw Logs page: near-black ground, green text
            c.setFillColorRGB(0.02, 0.035, 0.055)
            c.rect(MARGIN, box_top - box_h, CONTENT_W, box_h, stroke=0, fill=1)
            c.setStrokeColorRGB(*RULE)
            c.setLineWidth(0.7)
            c.rect(MARGIN, box_top - box_h, CONTENT_W, box_h, stroke=1, fill=0)
            c.setFont("Courier", 9)
            yy = box_top - PAD - 10
            for k, ent in enumerate(page_entries):
                c.setFillColorRGB(0.29, 0.87, 0.50)
                for vl in ent:
                    c.drawString(MARGIN + PAD, yy, vl)
                    yy -= LINE_H
                if k < len(page_entries) - 1:
                    # a rule between entries, centred in the gap (equal air above and below)
                    ly = (yy + LINE_H) - 9.5
                    c.setStrokeColorRGB(0.32, 0.42, 0.52)
                    c.setLineWidth(0.8)
                    c.line(MARGIN + PAD, ly, MARGIN + CONTENT_W - PAD, ly)
                yy -= GAP        # blank space between one log line and the next
            self.y = box_top - box_h - 4
            if i < n:
                self._new_page()


# ------------------------------------------------------------------ content
def _render_event_sections(d, state):
    """Draw one event's full detail sections onto an existing _Doc. Shared by
    the single-event report and the per-event pages of the chain report."""
    # 1. Alert details -----------------------------------------------------
    alert_rows = [
        ("Event ID", f"#{state['event_id']}" if state.get("event_id") else "pending"),
        ("Attack Type", state.get("attack_type")),
        ("Detection Rule", state.get("rule")),
        ("Source IP", state.get("source_ip")),
        ("Destination IP", (state.get("asset") or {}).get("ip") or state.get("dest_ip")),
        ("Target Asset", "%s (criticality: %s)" % (((state.get("asset") or {}).get("name") or "Unknown"),
                                                  ((state.get("asset") or {}).get("criticality") or "unknown"))),
        ("Aggregated Logs", state.get("log_count")),
        ("First Seen", _local_dt(state.get("first_seen"))[0] or "—"),
        ("First Seen at", _local_dt(state.get("first_seen"))[1] or "—"),
        ("Last Seen", _local_dt(state.get("last_seen"))[0] or "—"),
        ("Last Seen at", _local_dt(state.get("last_seen"))[1] or "—"),
    ]
    d.section("Alert Details", keep=d.kv_height(alert_rows))
    d.kv_table(alert_rows)

    # 2. Classification ----------------------------------------------------
    d.section("Threat Classification (XGBoost)", keep=70)
    d.confidence_bar(state.get("confidence"), state.get("risk"))

    # 3. AI analysis -------------------------------------------------------
    summary = state.get("llm_summary") or {}
    urgency = str(summary.get("urgency") or "").strip()
    ai_rows = [("What Happened", summary.get("what_happened")),
               ("Potential Impact", summary.get("what_could_go_wrong")),
               ("Recommended Action", summary.get("what_should_be_done"))]
    if urgency:
        ai_rows.append(("Urgency", urgency.upper()))
    d.section("AI Analysis", keep=d.kv_height(ai_rows))
    d.kv_table(ai_rows)

    # 4. MITRE -------------------------------------------------------------
    rows = []
    for entry in state.get("mitre_techniques") or []:
        tid, name = _split_technique(entry)
        rows.append((tid, name, _tactic_for(tid)))
    d.section("MITRE ATT&CK Techniques", keep=27 + max(len(rows), 1) * 30 + 8)
    d.data_table(["Technique ID", "Technique", "Tactic"], rows, [95, 260, 150])

    # 5. Attack chain ------------------------------------------------------
    if state.get("is_multistage") or state.get("chain_stages"):
        stages = []
        for i, stage in enumerate(state.get("chain_stages") or [], start=1):
            sd, stt = _local_dt(stage.get("timestamp"))
            stages.append((i, stage.get("phase"), stage.get("attack_type"), sd or "-", stt or "-"))
        head_rows = [("Chain Risk", (state.get("chain_risk") or "?").upper()),
                     ("Chain Assessment",
                      state.get("chain_assessment") or "Multiple related stages observed.")]
        if state.get("predicted_next"):
            head_rows.append(("Predicted Next Stage",
                              f"Based on the observed progression, the next stage to watch for is "
                              f"{state['predicted_next']}."))
        d.section("Attack Chain", keep=d.kv_height(head_rows) + 27 + len(stages) * 30)
        # the summary rows and the stage table stack with no gap: ONE table
        d.kv_table(head_rows, gap=0)
        d.data_table(["#", "Kill Chain Phase", "Attack Type", "Date", "Time"],
                     stages, [30, 150, 150, 90, 85])

    # 7. Raw logs ----------------------------------------------------------
    sample = state.get("raw_log_sample") or state.get("raw_logs") or []
    d.section("Raw Log Sample", keep=30 + min(len(sample) or 1, 6) * 20)
    # no line count above the box, even when the pull was capped
    d.code_box(sample)

    # 8. Response ----------------------------------------------------------
    # written as plain sentences: what was done, is it blocked now, who decided,
    # was anyone told
    action = state.get("action_taken")
    ip = state.get("source_ip") or "the source address"
    who = state.get("decided_by")
    when = _fmt_ts(state.get("decided_at"), "")
    verb = {"approved": "approved the block", "dismissed": "marked this event as a false positive",
            "reopen": "undid the false-positive mark"}.get(state.get("decision_action") or "", "")

    still = ("The target server's firewall is dropping its traffic." if state.get("blocked")
             else "The block has since been lifted.")
    if action == "blocked" and state.get("blocked_by") == "auto":
        did = f"Blocked {ip} automatically, because the risk was high. {still}"
    elif action == "blocked":
        did = f"Blocked {ip}" + (f" after {who} approved it. " if who else ". ") + still
    elif action == "awaiting_approval":
        did = "Nothing yet. The risk was uncertain, so the event is waiting for an analyst to decide."
    elif action and action.startswith("dismissed"):
        did = f"Nothing. {who or 'An analyst'} marked this event as a false positive."
    elif action == "block lifted by analyst":
        did = f"The block on {ip} was lifted by {who or 'an analyst'}."
    elif action == "whitelisted":
        did = f"Nothing. {ip} is on the whitelist, so the event was recorded but not blocked and no alert was sent."
    else:
        did = "Nothing. The risk was low, so the event was only recorded."

    b_date, b_time = _local_dt(state.get("blocked_at")) if state.get("blocked") else ("", "")
    d_date, d_time = _local_dt(state.get("decided_at"))
    decision = ((f"{who} {verb}" if verb else f"{who} decided")
                + (f" on {d_date} {d_time}" if d_date else "") + "." if who else " ")
    response_rows = [
        ("CyREN action", did),
        ("Blocked", "Yes" if state.get("blocked") else "No"),
        ("Block date", b_date or " "),
        ("Block time", b_time or " "),
        ("Analyst decision", decision),
        ("Email notification", "Done" if action == "blocked" else "Not sent"),
    ]
    d.section("Response Actions", keep=d.kv_height(response_rows))
    d.kv_table(response_rows)

    # 9. what the analysts wrote on the event, then the case ticket
    _people_table(d, "Analyst Notes", state.get("notes"), "Note")
    _ticket_section(d, state)


def _people_table(d, title, items, col):
    """Discussion / notes as a dated table. Deleted entries stay as tombstones."""
    rows = []
    for c in items or []:
        dd, tt = _local_dt(c.get("created_at"))
        if c.get("deleted_by"):
            text = "(deleted by %s)" % c["deleted_by"]
        else:
            text = (c.get("text") or "") + (" (edited)" if c.get("edited") else "") + (" [image below]" if c.get("image") else "")
        rows.append([dd or "-", tt or "-", c.get("by") or "-", text])
    if rows:
        d.section(title, keep=27 + min(len(rows), 3) * 30 + 8)
        d.data_table(["Date", "Time", "By", col], rows, [66, 62, 80, 297])


def _ticket_section(d, state):
    """Shared "Case Ticket" block — owner (or unassigned), status, resolution."""
    tk = state.get("ticket")
    if not tk:
        return
    tk_rows = [
        ("Ticket", "T-%s" % tk.get("id")),
        ("Title", tk.get("title") or "—"),
        ("Owner", tk.get("owner") or "unassigned"),
        ("Status", (tk.get("status") or "").replace("_", " ")),
        ("Opened", _local_dt(tk.get("created_at"))[0] or "—"),
        ("Opened at", _local_dt(tk.get("created_at"))[1] or "—"),
    ]
    if tk.get("close_reason"):
        tk_rows.append(("Resolution", tk.get("close_reason")))
    if tk.get("close_note"):
        tk_rows.append(("Closing Note", tk.get("close_note")))
    if tk.get("closed_by"):
        cd, ct = _local_dt(tk.get("closed_at"))
        tk_rows.append(("Closed By", tk.get("closed_by")))
        tk_rows.append(("Closed on", (cd + " " + ct).strip() or "—"))
    d.section("Case Ticket", keep=d.kv_height(tk_rows))
    d.kv_table(tk_rows)
    _people_table(d, "Discussion", tk.get("comments"), "Message")


def _render(c, state, total_pages=None):
    d = _Doc(c, state, total_pages)
    _render_event_sections(d, state)
    d._close_section()


# ------------------------------------------------------- attack-chain report
def _render_chain(c, state, total_pages=None):
    """A chain-level incident report: the whole multi-stage attack from one
    source, its kill-chain timeline, every related event, and both predictions.
    When event_details are supplied, each related event's full detail page is
    appended, so the chain PDF is a complete dossier."""
    d = _Doc(c, state, total_pages)

    # 1. Chain summary
    summary_rows = [
        ("Chain", state.get("report_ref")),
        ("Source IP", state.get("source_ip")),
        ("Stages", state.get("stage_count")),
        ("Highest Risk", (state.get("chain_risk") or "—")),
        ("First Seen", _local_dt(state.get("first_seen"))[0] or "—"),
        ("First Seen at", _local_dt(state.get("first_seen"))[1] or "—"),
        ("Last Seen", _local_dt(state.get("last_seen"))[0] or "—"),
        ("Last Seen at", _local_dt(state.get("last_seen"))[1] or "—"),
    ]
    d.section("Chain Summary", keep=d.kv_height(summary_rows))
    d.kv_table(summary_rows)

    _ticket_section(d, state)   # case ticket for the whole chain / case export

    chain_risk = str(state.get("chain_risk") or "").lower()
    fill, text = RISK_COLORS.get({"critical": "high", "medium": "uncertain"}.get(chain_risk, chain_risk), (BAND, INK))
    d.para_box("Assessment",
               state.get("chain_assessment") or "Multiple related stages observed from one source.",
               pill=((state.get("chain_risk") or "?").upper(), fill, text))

    # 2. Kill-chain timeline (stages joined to their real events)
    stages = []
    for i, s in enumerate(state.get("stages") or [], start=1):
        stages.append((i, s.get("phase"), s.get("attack_type"),
                       ", ".join(s.get("mitre") or []) or "—",
                       s.get("log_count") if s.get("log_count") is not None else "—",
                       (s.get("risk") or "—")))
    d.section("Kill-Chain Timeline", keep=27 + max(len(stages), 1) * 30 + 8)
    d.data_table(["#", "Phase", "Attack Type", "MITRE", "Logs", "Risk"],
                 stages, [24, 120, 120, 120, 55, 66])

    # 3. Predictions
    d.section("Next-Step Prediction")
    d.para_box("Rule-based baseline (deterministic)",
               state.get("predicted_next") or "No further stage predicted.")
    ai = state.get("ai_prediction") or {}
    if ai.get("available"):
        conf = str(ai.get("confidence") or "—")
        conf_pct = {"HIGH": " (~85%)", "MEDIUM": " (~60%)", "LOW": " (~35%)"}.get(conf.upper(), "")
        d.para_box("AI deep prediction (LLM) — overall confidence",
                   f"The model rates the overall confidence of this forecast as {conf}{conf_pct}. "
                   f"The techniques below are the most probable next moves given the kill-chain observed "
                   f"so far, each with its own likelihood and the reason it is expected.")
        for i, t in enumerate(ai.get("next_techniques") or [], start=1):
            pill = None
            lk = t.get("likelihood")
            if lk not in (None, ""):
                try:
                    v = int(lk)
                    fill = (1.0, 0.322, 0.322) if v >= 70 else (YELLOW if v >= 45 else (0.024, 0.839, 0.627))
                    pill = (f"{v}%", fill, (1, 1, 1) if v >= 70 else INK)
                except (TypeError, ValueError):
                    pill = None
            title = f"{i}. {t.get('technique', '')}" + (f"   [{t.get('mitre', '')}]" if t.get("mitre") else "")
            d.para_box(title, "Why: " + str(t.get("why") or "—"), pill=pill)
        d.para_box("Watch for", ai.get("watch_for", "—"))
        d.para_box("Pre-emptive action", ai.get("preemptive_action", "—"))
    else:
        d.para_box("AI deep prediction",
                   "Not generated for this chain (run it from the Attack Chain page). "
                   "The deterministic baseline above is authoritative.")

    # 4. All related events
    ev_rows = []
    for e in state.get("events") or []:
        ev_rows.append((f"#{e.get('id')}", e.get("attack_type"), (e.get("risk") or "—"),
                        _fmt_conf(e.get("confidence")), (e.get("status") or "—"),
                        e.get("log_count")))
    d.section("Related Events", keep=27 + max(len(ev_rows), 1) * 30 + 8)
    d.data_table(["Event", "Attack Type", "Risk", "Conf.", "Status", "Logs"],
                 ev_rows, [55, 150, 70, 55, 90, 85])

    # full detail page for every related event (same content as clicking into
    # the event on the dashboard: classification, AI analysis, MITRE, logs, ...)
    details = state.get("event_details") or []
    for est in details:
        d._new_page()
        d.section("Event #%s Detail — %s" % (est.get("event_id") or "?",
                                             est.get("attack_type") or "Event"))
        _render_event_sections(d, est)
    d._close_section()


def generate_chain_report(state: dict) -> str:
    """Build the attack-chain PDF and return its path."""
    os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
    ref = (state.get("report_ref") or "chain").replace("#", "").replace(" ", "")
    path = os.path.join(settings.REPORT_OUTPUT_DIR,
                        f"CyREN_Chain_{ref}_{(state.get('source_ip') or 'unknown')}_{ts}_{REPORT_FORMAT_VERSION}.pdf")
    if _canvas is None:
        path = path.replace(".pdf", ".txt")
        with open(path, "w") as fh:
            fh.write(f"Attack chain report placeholder for {state.get('source_ip')}\n")
        return path
    probe = _canvas.Canvas(io.BytesIO(), pagesize=A4)
    _render_chain(probe, state)
    total = probe.getPageNumber()
    c = _canvas.Canvas(path, pagesize=A4)
    c.setTitle(f"CyREN Attack Chain Report - {(state.get('source_ip') or 'unknown')}")
    c.setAuthor("CyREN SOC Incident Response")
    _render_chain(c, state, total_pages=total)
    c.save()
    return path


def generate_report(state: dict) -> str:
    os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
    filename = (f"CyREN_Incident_{(state.get('source_ip') or 'unknown')}_{ts}"
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
    c.setTitle(f"CyREN Incident Report - {(state.get('source_ip') or 'unknown')}")
    c.setAuthor("CyREN SOC Incident Response")
    _render(c, state, total_pages=total)
    c.save()
    return path


# --------------------------------------------------------- SOC activity report
ACTIVITY_DEFAULT_ORDER = ["summary", "analyst", "tickets", "events", "chains", "blocks", "audit", "assets", "rawlogs"]


def _render_activity(c, state, total_pages=None):
    """A period 'situation report': whichever sections the user selected, in the
    same styled layout as an incident report."""
    d = _Doc(c, state, total_pages)
    secs = state.get("sections") or {}

    # every section is a function, so the report can follow the order the
    # user chose in the Report Builder (state['order']); DEFAULT_ORDER otherwise
    def s_summary():
        if "summary" in secs:
            s = secs["summary"]
            rows = [
                ("Logs collected", s.get("logs_collected")),
                ("Security events", s.get("security_events")),
                ("High risk", s.get("high_risk")),
                ("Uncertain risk", s.get("uncertain_risk")),
                ("Low risk", s.get("low_risk")),
                ("Awaiting approval", s.get("awaiting")),
                ("Blocked", s.get("blocked")),
            ]
            d.section("Summary", keep=d.kv_height(rows))
            d.kv_table(rows)

    def s_tickets():
        for tk in secs.get("ticket_details") or []:
            d._new_page()
            rows = [("Ticket", "T-%s" % tk.get("id")),
                    ("Title", tk.get("title") or "—"),
                    ("Owner", tk.get("owner") or "unassigned"),
                    ("Status", (tk.get("status") or "").replace("_", " ")),
                    ("Risk", tk.get("risk") or "-"),
                    ("Source IP", tk.get("source_ip") or "-"),
                    ("Opened", _local_dt(tk.get("created_at"))[0] or "—"),
                    ("Opened at", _local_dt(tk.get("created_at"))[1] or "—"),
                    ("Events", ", ".join(tk.get("events") or []) or "-")]
            if tk.get("description"):          # part of the same table, not a box under it
                rows.append(("Description", tk.get("description")))
            if tk.get("close_reason"):
                rows.append(("Resolution", tk.get("close_reason")))
            if tk.get("close_note"):
                rows.append(("Closing Note", tk.get("close_note")))
            if tk.get("closed_by"):
                cd, ct = _local_dt(tk.get("closed_at"))
                rows.append(("Closed By", tk.get("closed_by")))
                rows.append(("Closed on", (cd + " " + ct).strip() or "—"))
            d.section("Ticket T-%s" % tk.get("id"), keep=d.kv_height(rows))
            d.kv_table(rows)
            _people_table(d, "Discussion", tk.get("comments"), "Message")
            act = tk.get("activity") or []
            if act:
                d.section("Response History (who & when)", keep=27 + min(len(act), 3) * 30 + 8)
                d.data_table(["Date", "Time", "Action", "By"], act, [66, 56, 300, 83])
            fw = tk.get("response_log") or []
            if fw:
                d.section("Firewall Response Log", keep=27 + min(len(fw), 3) * 30 + 8)
                d.data_table(["Date", "Time", "Action", "Detail"], fw, [66, 56, 100, 283])

        if "tickets" in secs and not secs.get("ticket_details"):
            rows = secs["tickets"]
            d.section("Tickets", keep=27 + max(len(rows), 1) * 30 + 8)
            d.data_table(["Ticket", "Date", "Time", "Title", "Source IP", "Risk", "Status", "Assignee"],
                         rows, [40, 66, 56, 110, 85, 45, 50, 55])

    def s_events():
        for est in secs.get("event_details") or []:
            d._new_page()
            d.section("Event #%s Detail — %s" % (est.get("event_id") or "?",
                                                 est.get("attack_type") or "Event"))
            _render_event_sections(d, est)
        if "events" in secs and not secs.get("event_details"):
            rows = secs["events"]
            d.section("Security Events", keep=27 + max(len(rows), 1) * 30 + 8)
            d.data_table(["#", "Date", "Time", "Source IP", "Attack Type", "Risk", "Conf.", "Status"],
                         rows, [34, 66, 56, 88, 105, 55, 42, 60])

    def s_chains():
        for chd in secs.get("chain_details") or []:
            d._new_page()
            rows = [("Chain", chd.get("ref")), ("Source IP", chd.get("source_ip")),
                    ("Highest Risk", chd.get("risk")),
                    ("First Seen", chd.get("first_date")), ("First Seen at", chd.get("first_time")),
                    ("Last Seen", chd.get("last_date")), ("Last Seen at", chd.get("last_time")),
                    ("Ticket", chd.get("ticket"))]
            if chd.get("predicted_next"):
                rows.append(("Predicted Next", chd.get("predicted_next")))
            d.section("Attack Chain %s — %s" % (chd.get("ref"), chd.get("source_ip") or ""),
                      keep=d.kv_height(rows))
            d.kv_table(rows)
            st = chd.get("stages") or []
            d.section("Kill-Chain Timeline", keep=27 + max(len(st), 1) * 30 + 8)
            d.data_table(["#", "Phase", "Attack Type", "MITRE", "Date", "Time"],
                         st, [24, 105, 120, 120, 70, 66])

        if "chains" in secs and not secs.get("chain_details"):
            rows = secs["chains"]
            d.section("Attack Chains", keep=27 + max(len(rows), 1) * 30 + 8)
            d.data_table(["Chain", "Source IP", "Stages", "Risk", "First Date", "First Time",
                          "Last Date", "Last Time", "Ticket"],
                         rows, [45, 88, 42, 55, 66, 56, 66, 56, 45])

    def s_blocks():
        if "blocks" in secs:
            rows = secs["blocks"]
            d.section("Firewall Blocks", keep=27 + max(len(rows), 1) * 30 + 8)
            d.data_table(["IP", "Attack Type", "By", "Active", "Date", "Time"],
                         rows, [95, 140, 70, 50, 78, 72])

    def s_audit():
        if "audit" in secs:
            rows = secs["audit"]
            d.section("Audit Log", keep=27 + max(len(rows), 1) * 30 + 8)
            d.data_table(["Date", "Time", "Action", "Details", "Taken By"], rows, [66, 56, 100, 200, 83])

    def s_assets():
        if "assets" in secs:
            rows = secs["assets"]
            d.section("Assets", keep=27 + max(len(rows), 1) * 30 + 8)
            d.data_table(["IP", "Name", "Criticality", "Department", "Owner", "Description"],
                         rows, [90, 100, 75, 95, 70, 75])

    def s_rawlogs():
        if "rawlogs" in secs:            # last: the longest and least summarised part
            rows = secs["rawlogs"]
            d.section("Raw Logs (SIEM)", keep=27 + 30 + 8)
            d.data_table(["Date", "Time", "Source IP", "Log Message"], rows, [70, 62, 88, 285])

    def s_analyst():
        notes = state.get("analyst_notes") or []
        if notes:
            # a table under the bar, like the Discussion; images follow as boxes
            _people_table(d, "Analyst Comments", notes, "Comment")
            for n in notes:
                if n.get("image"):
                    d.note_block(n, attachment_only=True)

    render = {"summary": s_summary, "analyst": s_analyst, "tickets": s_tickets, "events": s_events,
              "chains": s_chains, "blocks": s_blocks, "audit": s_audit, "assets": s_assets, "rawlogs": s_rawlogs}
    order = [k for k in (state.get("order") or []) if k in render]
    order += [k for k in ACTIVITY_DEFAULT_ORDER if k not in order]
    for k in order:
        render[k]()
    d._close_section()


def render_activity_report_bytes(state: dict) -> bytes:
    """Render a SOC activity report to PDF bytes (nothing written to disk)."""
    if _canvas is None:
        return b""
    probe = _canvas.Canvas(io.BytesIO(), pagesize=A4)
    _render_activity(probe, state)
    total = probe.getPageNumber()
    buf = io.BytesIO()
    c = _canvas.Canvas(buf, pagesize=A4)
    c.setTitle("CyREN SOC Activity Report")
    c.setAuthor("CyREN SOC Incident Response")
    _render_activity(c, state, total_pages=total)
    c.save()
    buf.seek(0)
    return buf.getvalue()
