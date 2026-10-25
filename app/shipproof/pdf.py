"""PDF report generator — pure Python, zero dependencies.

We draw the report ourselves with PDF primitives (rect / line / text) using the
two standard Helvetica fonts that every PDF reader has built in. No WeasyPrint,
no headless Chrome, no system packages.
"""
from __future__ import annotations

import datetime

from . import config

A4_W, A4_H = 595.28, 841.89
MARGIN = 46.0
CONTENT_W = A4_W - 2 * MARGIN

NAVY = (0.043, 0.063, 0.125)
NAVY_SOFT = (0.06, 0.09, 0.17)
WHITE = (1.0, 1.0, 1.0)
TEAL = (0.369, 0.918, 0.831)
INDIGO = (0.506, 0.549, 0.973)
MUTED = (0.55, 0.61, 0.70)
DARK = (0.08, 0.11, 0.17)
DANGER = (1.0, 0.30, 0.43)
HIGH = (1.0, 0.62, 0.26)
MEDIUM = (1.0, 0.85, 0.24)
LOW = (0.42, 0.80, 1.0)
INFO = (0.55, 0.58, 0.65)
OK = (0.20, 0.83, 0.60)

SEV_COLOR = {"critical": DANGER, "high": HIGH, "medium": MEDIUM, "low": LOW, "info": INFO}
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}

REPLACEMENTS = {
    "₹": "Rs. ", "—": "-", "–": "-", "’": "'", "‘": "'", "“": '"', "”": '"',
    "…": "...", "·": "-", "→": "->", "≤": "<=", "≥": ">=", "\u00a0": " ",
    "•": "-", "✓": "v", "✕": "x", "🔒": "", "🛡": "", "️": "",
}


def _fold(text: str) -> str:
    for key, value in REPLACEMENTS.items():
        text = text.replace(key, value)
    text = text.encode("latin-1", "replace").decode("latin-1")
    return "".join(ch if 32 <= ord(ch) < 255 else "?" for ch in text)


def _esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(text: str, size: float, width: float, bold: bool = False) -> list[str]:
    factor = 0.53 if bold else 0.495
    max_chars = max(10, int(width / (size * factor)))
    lines: list[str] = []
    for paragraph in str(text or "").split("\n"):
        words = paragraph.split()
        current = ""
        for word in words:
            candidate = (current + " " + word).strip()
            if len(candidate) <= max_chars:
                current = candidate
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
    return lines or [""]


class Page:
    def __init__(self) -> None:
        self.ops: list[str] = []

    def rect(self, x: float, y: float, w: float, h: float, color) -> None:
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f")

    def stroke_rect(self, x: float, y: float, w: float, h: float, color, width: float = 0.7) -> None:
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG {width} w {x:.2f} {y:.2f} {w:.2f} {h:.2f} re S")

    def line(self, x1: float, y1: float, x2: float, y2: float, color, width: float = 0.7) -> None:
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG {width} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def circle(self, cx: float, cy: float, radius: float, color, fill: bool = True, width: float = 1.2) -> None:
        k = 0.5523 * radius
        r, g, b = color
        head = f"{r:.3f} {g:.3f} {b:.3f} " + ("rg " if fill else f"RG {width} w ")
        ops = head + f"{cx + radius:.2f} {cy:.2f} m "
        ops += f"{cx + radius:.2f} {cy + k:.2f} {cx + k:.2f} {cy + radius:.2f} {cx:.2f} {cy + radius:.2f} c "
        ops += f"{cx - k:.2f} {cy + radius:.2f} {cx - radius:.2f} {cy + k:.2f} {cx - radius:.2f} {cy:.2f} c "
        ops += f"{cx - radius:.2f} {cy - k:.2f} {cx - k:.2f} {cy - radius:.2f} {cx:.2f} {cy - radius:.2f} c "
        ops += f"{cx + k:.2f} {cy - radius:.2f} {cx + radius:.2f} {cy - k:.2f} {cx + radius:.2f} {cy:.2f} c " + ("f" if fill else "S")
        self.ops.append(ops)

    def text(self, x: float, y: float, size: float, text: str, bold: bool = False, color=DARK) -> None:
        if text is None or text == "":
            return
        r, g, b = color
        font = "/F2" if bold else "/F1"
        payload = _esc(_fold(str(text)))
        self.ops.append(
            f"BT {r:.3f} {g:.3f} {b:.3f} rg {font} {size:.1f} Tf 1 0 0 1 {x:.2f} {y:.2f} Tm ({payload}) Tj ET"
        )

    def content(self) -> bytes:
        return "\n".join(self.ops).encode("latin-1", "replace")


class Doc:
    def __init__(self) -> None:
        self.pages: list[Page] = []

    def new_page(self) -> Page:
        page = Page()
        self.pages.append(page)
        return page

    def build(self) -> bytes:
        objects: dict[int, bytes] = {}
        objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
        kids = " ".join(f"{5 + 2 * i} 0 R" for i in range(len(self.pages)))
        objects[2] = f"<< /Type /Pages /Count {len(self.pages)} /Kids [{kids}] >>".encode()
        objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        objects[4] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
        for index, page in enumerate(self.pages):
            page_num = 5 + 2 * index
            content_num = page_num + 1
            content = page.content()
            objects[page_num] = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {A4_W:.2f} {A4_H:.2f}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_num} 0 R >>"
            ).encode()
            objects[content_num] = (
                b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream"
            )
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: dict[int, int] = {}
        for num in sorted(objects):
            offsets[num] = len(out)
            out += f"{num} 0 obj\n".encode() + objects[num] + b"\nendobj\n"
        xref = len(out)
        count = max(objects) + 1
        out += f"xref\n0 {count}\n".encode() + b"0000000000 65535 f \n"
        for num in range(1, count):
            out += f"{offsets.get(num, 0):010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return bytes(out)


# --------------------------------------------------------------------------
# report layout
# --------------------------------------------------------------------------


def _footer(page: Page, record: dict, page_no: int, total: int) -> None:
    page.line(MARGIN, 34, A4_W - MARGIN, 34, (0.85, 0.88, 0.92), 0.5)
    page.text(MARGIN, 22, 7.5, f"{config.BRAND} - independent check, not a penetration test · wrong finding? {config.CONTACT_EMAIL}", color=MUTED)
    page.text(A4_W - MARGIN - 60, 22, 7.5, f"{page_no}/{total}", color=MUTED)


def _cover(doc: Doc, record: dict, score: dict) -> None:
    page = doc.new_page()
    page.rect(0, 0, A4_W, A4_H, NAVY)
    page.rect(0, A4_H - 6, A4_W, 6, TEAL)

    # shield mark
    page.circle(MARGIN + 16, A4_H - 78, 16, TEAL)
    page.text(MARGIN + 8.5, A4_H - 84, 15, "v", bold=True, color=NAVY)
    page.text(MARGIN + 42, A4_H - 74, 22, config.BRAND, bold=True, color=WHITE)
    page.text(MARGIN + 42, A4_H - 92, 9, "INDEPENDENT SECURITY VERIFICATION", color=TEAL)

    page.text(MARGIN, A4_H - 150, 10, "SECURITY & AI-SAFETY REPORT", bold=True, color=TEAL)
    y = A4_H - 185
    for line in _wrap(record.get("target", ""), 17, CONTENT_W - 80, bold=True)[:3]:
        page.text(MARGIN, y, 17, line, bold=True, color=WHITE)
        y -= 22
    scanned = str(record.get("created_at", ""))[:10]
    kind = "LIVE URL" if record.get("kind") == "url" else "GITHUB REPOSITORY"
    page.text(MARGIN, y - 4, 9, f"{kind}   -   {scanned}   -   {len(record.get('findings') or [])} findings", color=MUTED)

    # score block
    cx, cy = A4_W - MARGIN - 70, A4_H - 300
    page.circle(cx, cy, 62, (0.13, 0.18, 0.30))
    page.circle(cx, cy, 62, TEAL, fill=False, width=2.4)
    page.text(cx - 22, cy - 4, 40, str(score.get("score", 0)), bold=True, color=WHITE)
    page.text(cx - 18, cy - 24, 10, str(score.get("grade", "")), color=TEAL)
    page.text(cx - 34, cy - 44, 7.5, "SCORE / 100", color=MUTED)

    verdict_y = cy - 120
    page.text(MARGIN, verdict_y, 11, "VERDICT", bold=True, color=TEAL)
    vy = verdict_y - 18
    for line in _wrap(score.get("headline", ""), 14, CONTENT_W - 40, bold=True)[:2]:
        page.text(MARGIN, vy, 14, line, bold=True, color=WHITE)
        vy -= 19
    for line in _wrap(score.get("verdict", ""), 10, CONTENT_W - 60)[:3]:
        page.text(MARGIN, vy - 4, 10, line, color=(0.78, 0.83, 0.90))
        vy -= 15

    # counts strip
    counts = score.get("counts") or {}
    strip_y = 250
    page.rect(MARGIN, strip_y, CONTENT_W, 64, NAVY_SOFT)
    labels = [("critical", "CRITICAL"), ("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW")]
    step = CONTENT_W / len(labels)
    for index, (key, label) in enumerate(labels):
        x = MARGIN + step * index + 16
        page.text(x, strip_y + 34, 20, str(counts.get(key, 0)), bold=True, color=SEV_COLOR[key])
        page.text(x, strip_y + 16, 8, label, color=MUTED)

    page.text(MARGIN, 200, 9, "PREPARED BY", color=MUTED)
    page.text(MARGIN, 184, 12, config.BRAND, bold=True, color=WHITE)
    page.text(MARGIN, 168, 8.5, config.BASE_URL.replace("https://", "").replace("http://", ""), color=TEAL)
    page.text(MARGIN, 120, 8.5, "Report ID " + str(record.get("id", "")), color=MUTED)
    page.text(MARGIN, 106, 8.5, "Verified badge valid for 14 days from the scan date.", color=MUTED)
    page.text(MARGIN, 60, 7.5, "This is an automated external check, not a penetration test or a guarantee.", color=(0.55, 0.60, 0.68))


def _summary(doc: Doc, record: dict, score: dict, page_no: int, total_pages: int) -> None:
    page = doc.new_page()
    page.rect(0, A4_H - 5, A4_W, 5, TEAL)
    page.text(MARGIN, A4_H - 62, 20, "Summary", bold=True, color=DARK)
    page.line(MARGIN, A4_H - 72, A4_W - MARGIN, A4_H - 72, (0.85, 0.88, 0.92), 0.6)

    y = A4_H - 100
    checks = record.get("checks") or []
    passed = sum(1 for check in checks if check.get("ok"))
    page.text(MARGIN, y, 9, f"{len(checks)} checks run  -  {passed} passed  -  score {score.get('score')}/100 ({score.get('grade')})", color=MUTED)
    if record.get("prepared_for"):
        y -= 15
        page.text(MARGIN, y, 8.5, f"Prepared for {record.get('prepared_for')}"
                  + (f" - handover by {record.get('agency_name')}" if record.get("agency_name") else ""),
                  color=(0.20, 0.45, 0.42))

    # risk boxes
    y -= 24
    risks = [("MONEY RISK", score.get("cost_risk") or {}), ("DATA RISK", score.get("breach_risk") or {})]
    box_w = (CONTENT_W - 12) / 2
    for index, (label, risk) in enumerate(risks):
        x = MARGIN + (box_w + 12) * index
        page.rect(x, y - 66, box_w, 66, (0.96, 0.97, 0.99))
        page.stroke_rect(x, y - 66, box_w, 66, (0.86, 0.89, 0.93))
        page.text(x + 12, y - 18, 7.5, label, bold=True, color=MUTED)
        page.text(x + 12, y - 34, 11, str(risk.get("title", "")), bold=True, color=DARK)
        for line in _wrap(risk.get("explain", ""), 8, box_w - 24)[:2]:
            page.text(x + 12, y - 48, 8, line, color=(0.35, 0.40, 0.48))
            y -= 10
        y = y if index == 0 else y
        if index == 0:
            y -= 0
    y -= 92

    # English verdict
    page.text(MARGIN, y, 10, "In plain English", bold=True, color=(0.32, 0.35, 0.85))
    y -= 16
    for line in _wrap(score.get("summary_en") or score.get("summary_hi", ""), 9.5, CONTENT_W)[:5]:
        page.text(MARGIN, y, 9.5, line, color=(0.20, 0.24, 0.32))
        y -= 14
    y -= 14

    # top actions
    page.text(MARGIN, y, 12, "Fix these first", bold=True, color=DARK)
    y -= 20
    for index, action in enumerate((score.get("top_actions") or [])[:3], 1):
        page.circle(MARGIN + 7, y - 2, 7, TEAL)
        page.text(MARGIN + 4.5, y - 5, 8, str(index), bold=True, color=NAVY)
        page.text(MARGIN + 22, y - 1, 10, action.get("title", ""), bold=True, color=DARK)
        page.text(MARGIN + 22, y - 14, 8, f"{action.get('severity', '')}  -  ~{action.get('effort', '')}", color=MUTED)
        y -= 34
    y -= 8

    # table of contents hint
    page.rect(MARGIN, y - 58, CONTENT_W, 58, (0.97, 0.98, 0.99))
    page.text(MARGIN + 12, y - 18, 8, "WHAT IS INSIDE", bold=True, color=MUTED)
    page.text(MARGIN + 12, y - 32, 9, f"Full findings (page 3+)  -  {len(record.get('findings') or [])} issues with evidence and fixes", color=DARK)
    page.text(MARGIN + 12, y - 46, 9, "What we could not check  -  honest limits of an external scan", color=DARK)

    _footer(page, record, page_no, total_pages)


def _findings(doc: Doc, record: dict, start_page: int, total_pages: int) -> None:
    findings = record.get("findings") or []
    page = doc.new_page()
    page.rect(0, A4_H - 5, A4_W, 5, TEAL)
    page.text(MARGIN, A4_H - 62, 20, "Findings", bold=True, color=DARK)
    page.text(MARGIN, A4_H - 80, 9, f"{len(findings)} issues, worst first. Evidence and fix for each.", color=MUTED)
    page.line(MARGIN, A4_H - 90, A4_W - MARGIN, A4_H - 90, (0.85, 0.88, 0.92), 0.6)
    y = A4_H - 112

    for finding in findings[:30]:
        severity = finding.get("severity", "info")
        color = SEV_COLOR.get(severity, INFO)
        needed = 88
        if y - needed < 60:
            _footer(page, record, start_page + len(doc.pages) - start_page, total_pages)
            page = doc.new_page()
            page.rect(0, A4_H - 5, A4_W, 5, TEAL)
            page.text(MARGIN, A4_H - 62, 16, "Findings (continued)", bold=True, color=DARK)
            page.line(MARGIN, A4_H - 74, A4_W - MARGIN, A4_H - 74, (0.85, 0.88, 0.92), 0.6)
            y = A4_H - 96
        page.rect(MARGIN, y - 12, 3, 12, color)
        page.text(MARGIN + 10, y - 10, 8, SEV_LABEL.get(severity, "INFO"), bold=True, color=color)
        title_lines = _wrap(finding.get("title", ""), 11, CONTENT_W - 90, bold=True)
        page.text(MARGIN + 70, y - 10, 11, title_lines[0], bold=True, color=DARK)
        page.text(A4_W - MARGIN - 62, y - 10, 8, f"~{finding.get('effort', '')}", color=MUTED)
        y -= 24
        for line in title_lines[1:]:
            page.text(MARGIN + 70, y - 8, 11, line, bold=True, color=DARK)
            y -= 15
        meta = f"{finding.get('category', '')}  -  confidence {finding.get('confidence', 'high')}"
        page.text(MARGIN + 10, y - 6, 7.5, meta, color=MUTED)
        y -= 16

        evidence = finding.get("evidence", "")
        if evidence:
            page.text(MARGIN + 10, y - 6, 7, "EVIDENCE", bold=True, color=MUTED)
            y -= 11
            for line in _wrap(evidence, 8, CONTENT_W - 20)[:4]:
                page.text(MARGIN + 10, y - 6, 8, line, color=(0.30, 0.34, 0.42))
                y -= 11
            y -= 2
        for line in _wrap(finding.get("why", ""), 8.5, CONTENT_W - 20)[:5]:
            page.text(MARGIN + 10, y - 6, 8.5, line, color=(0.25, 0.29, 0.37))
            y -= 12
        page.text(MARGIN + 10, y - 6, 7, "FIX", bold=True, color=(0.15, 0.62, 0.55))
        y -= 11
        for line in _wrap(finding.get("fix", ""), 8.5, CONTENT_W - 20)[:6]:
            page.text(MARGIN + 10, y - 6, 8.5, line, color=(0.12, 0.32, 0.30))
            y -= 12
        y -= 8
        page.line(MARGIN, y, A4_W - MARGIN, y, (0.90, 0.92, 0.95), 0.5)
        y -= 16

    if len(findings) > 30:
        page.text(MARGIN, y, 8.5, f"...and {len(findings) - 30} more findings in the online report.", color=MUTED)
    _footer(page, record, total_pages - 1, total_pages)


def _last_page(doc: Doc, record: dict, page_no: int, total_pages: int) -> None:
    page = doc.new_page()
    page.rect(0, A4_H - 5, A4_W, 5, TEAL)
    page.text(MARGIN, A4_H - 62, 20, "Next steps", bold=True, color=DARK)
    page.line(MARGIN, A4_H - 72, A4_W - MARGIN, A4_H - 72, (0.85, 0.88, 0.92), 0.6)
    y = A4_H - 100
    steps = [
        ("1. Fix the critical and high items first.", "Each one is a way in. Copy the fix prompt from the online report into Cursor/Lovable/Bolt."),
        ("2. Re-scan after you deploy.", f"Open {config.BASE_URL.replace('https://', '').replace('http://', '')} and run the scan again - the score should move."),
        ("3. Put the badge on your site.", "A dated, verifiable proof page turns a claim into evidence. It expires, so you keep re-checking."),
    ]
    for title, body in steps:
        page.text(MARGIN, y, 11, title, bold=True, color=DARK)
        yy = y - 16
        for line in _wrap(body, 9, CONTENT_W - 10)[:4]:
            page.text(MARGIN, yy, 9, line, color=(0.30, 0.34, 0.42))
            yy -= 13
        y = yy - 12

    y -= 8
    page.text(MARGIN, y, 12, "What this scan could not check", bold=True, color=DARK)
    y -= 18
    for item in config.NOT_CHECKED:
        page.text(MARGIN, y, 8.5, "-  " + item, color=(0.35, 0.39, 0.47))
        y -= 12

    y -= 16
    page.rect(MARGIN, y - 70, CONTENT_W, 70, (0.94, 0.99, 0.98))
    page.text(MARGIN + 12, y - 20, 9, "Need this watched, not just scanned?", bold=True, color=(0.06, 0.32, 0.29))
    page.text(MARGIN + 12, y - 36, 8.5, f"Watch plan: weekly re-scan, email alerts, badge stays current - Rs. {config.WATCH_INR}/month.", color=(0.12, 0.40, 0.37))
    page.text(MARGIN + 12, y - 52, 8.5, "Agencies: white-label audits for every client handover.", color=(0.12, 0.40, 0.37))

    page.text(MARGIN, 86, 8, "Report " + str(record.get("id", "")) + "  -  generated by " + config.BRAND, color=MUTED)
    page.text(MARGIN, 74, 8, "A check is a point in time, not a promise about the future.", color=MUTED)
    _footer(page, record, page_no, total_pages)


def build_report_pdf(record: dict) -> bytes:
    score = record.get("score") or {}
    doc = Doc()
    _cover(doc, record, score)
    # page count: cover + summary + findings pages + last. Estimate generously,
    # then rebuild with the real count for the footer.
    estimate = 3 + max(1, (len(record.get("findings") or []) + 1) // 8)
    _summary(doc, record, score, 2, estimate)
    _findings(doc, record, 3, estimate)
    _last_page(doc, record, len(doc.pages) + 1, len(doc.pages) + 1)
    total = len(doc.pages)
    # Re-render with the correct total in footers (cheap: rebuild once).
    doc = Doc()
    _cover(doc, record, score)
    _summary(doc, record, score, 2, total)
    _findings(doc, record, 3, total)
    _last_page(doc, record, total, total)
    return doc.build()


def generated_at() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
