"""One-click incident report: a PDF a person can hand to a manager or attach to a ticket."""
import os
from datetime import datetime

from fpdf import FPDF
from fpdf.enums import XPos, YPos

FONTS = os.path.join(os.path.dirname(__file__), "fonts")
NAVY, BRASS, FLARE, MOSS, SLATE, BODY, RULE, MIST = (11, 31, 58), (201, 162, 39), (196, 61, 43), (46, 139, 98), \
    (91, 107, 127), (38, 54, 74), (215, 222, 231), (238, 242, 246)
SEV = {"critical": ("Critical", FLARE), "high": ("High", (224, 123, 38)), "medium": ("Medium", (154, 122, 10)),
       "low": ("Low", SLATE)}
STATUS = {"new": "Waiting for a person to review", "real": "Confirmed as a real threat", "false": "Marked as a false alarm",
          "resolved": "Dealt with"}


def _glyphs():
    try:
        from fontTools.ttLib import TTFont
        out = set()
        for f in ("IBMPlexSans-400.ttf", "IBMPlexMono-400.ttf"):
            out |= set(TTFont(os.path.join(FONTS, f)).getBestCmap())
        return out
    except Exception:
        return set(range(32, 127))


GLYPHS = _glyphs()
SWAP = {"→": "->", "←": "<-", "…": "...", "×": "x"}


def clean(s):
    s = "" if s is None else str(s)
    for a, b in SWAP.items():
        if ord(a) not in GLYPHS:
            s = s.replace(a, b)
    return "".join(c if ord(c) in GLYPHS or c == "\n" else "?" for c in s)


def nice_time(iso):
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %Y, %H:%M:%S")
    except Exception:
        return iso or "-"


class Report(FPDF):
    def __init__(self, alert_id):
        super().__init__(format="A4")
        self.alert_id = alert_id
        self.add_font("Plex", "", os.path.join(FONTS, "IBMPlexSans-400.ttf"))
        self.add_font("Plex", "B", os.path.join(FONTS, "IBMPlexSans-600.ttf"))
        self.add_font("PlexBold", "", os.path.join(FONTS, "IBMPlexSans-700.ttf"))
        self.add_font("Mono", "", os.path.join(FONTS, "IBMPlexMono-400.ttf"))
        self.set_margins(16, 16, 16)
        self.set_auto_page_break(True, 18)

    def header(self):
        self.set_fill_color(*NAVY)
        self.rect(0, 0, 210, 22, "F")
        self.set_fill_color(*BRASS)
        self.rect(0, 22, 210, 1.2, "F")
        self.set_xy(16, 7)
        self.set_text_color(255, 255, 255)
        self.set_font("Plex", "B", 12)
        self.cell(120, 8, "Security Log Monitor  |  Incident report")
        self.set_font("Plex", "", 9)
        self.set_text_color(185, 199, 216)
        self.set_xy(110, 7)
        self.cell(84, 8, f"Threat #{self.alert_id}  |  made {datetime.now():%d %b %Y, %H:%M}", align="R")
        self.set_y(30)

    def footer(self):
        self.set_y(-13)
        self.set_font("Plex", "", 8)
        self.set_text_color(*SLATE)
        self.cell(0, 5, "Made by the Security Log Monitor (FYP1 prototype, Universiti Malaya). "
                        "The AI does a first check. A person still decides what matters.", align="L")
        self.cell(0, 5, f"Page {self.page_no()}", align="R")

    # ---- building blocks -------------------------------------------------------------
    def heading(self, text, size=12.5, gap=5):
        self.ln(gap)
        if self.get_y() > 260:
            self.add_page()
        self.set_font("Plex", "B", size)
        self.set_text_color(*NAVY)
        self.multi_cell(0, 6.5, clean(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def para(self, text, size=10.5, color=BODY):
        self.set_font("Plex", "", size)
        self.set_text_color(*color)
        self.multi_cell(0, 5.4, clean(text), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def fit(self, text, width):
        """Cut text so it fits in width (mm) with the current font."""
        text = clean(text)
        if self.get_string_width(text) <= width:
            return text
        while text and self.get_string_width(text + "...") > width:
            text = text[:-1]
        return text + "..."

    def bullets(self, items):
        self.set_font("Plex", "", 10.5)
        self.set_text_color(*BODY)
        for t in items:
            self.set_x(self.l_margin)
            self.cell(5, 5.4, "-")
            self.multi_cell(0, 5.4, clean(t), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def chip(self, text, color, x, y):
        self.set_font("Plex", "B", 9)
        w = self.get_string_width(clean(text)) + 7
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_xy(x, y)
        self.cell(w, 6, clean(text), align="C", fill=True)
        return x + w + 2.5


def build(d, story, profile, blocked=None):
    """d: alert_detail, story: Monitor.story, profile: Monitor.entity_profile (may be None)."""
    pdf = Report(d["id"])
    pdf.add_page()
    sev_name, sev_col = SEV.get(d["severity"], ("Medium", BRASS))
    x = pdf.chip(sev_name, sev_col, 16, pdf.get_y())
    x = pdf.chip("Spotted by the AI" if d["kind"] == "ai" else "Known attack pattern", (31, 78, 140), x, pdf.get_y())
    if d.get("learned"):
        pdf.chip("Learned from a person's answer", MOSS, x, pdf.get_y())
    pdf.ln(9)
    pdf.set_font("PlexBold", "", 19)
    pdf.set_text_color(*NAVY)
    pdf.multi_cell(0, 8.5, clean(d["title"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    who = d["entity"]
    who_text = f"user {who[5:]}" if who.startswith("user:") else f"machine {who[5:]}" if who.startswith("host:") else who
    geo = (profile or {}).get("geo") or {}
    facts = [("Who", who_text), ("Location", geo.get("country") or "-"), ("Seen in", d.get("source_name") or "-"),
             ("First seen (log time)", nice_time(d["first_ts"])), ("Last seen (log time)", nice_time(d["last_ts"])),
             ("Times seen", f"{d['count']}"), ("Risk score now", f"{profile['risk']} of 100 ({profile['band_text']})" if profile else "-"),
             ("Status", STATUS.get(d["status"], d["status"]))]
    if blocked:
        facts.append(("Response", f"Address blocked until {datetime.fromtimestamp(blocked['until']):%H:%M}"
                                  f" ({ {'lab': 'by the attack lab firewall', 'firewall': 'by a Windows Firewall rule'}.get(blocked['mode'], 'simulated') })"))
    if d.get("mitre"):
        facts.append(("Method" if d["kind"] == "ai" else "MITRE ATT&CK", d["mitre"]))
    pdf.set_draw_color(*RULE)
    for i, (k, v) in enumerate(facts):
        y = pdf.get_y()
        if i % 2 == 0:
            pdf.set_fill_color(*MIST)
            pdf.rect(16, y, 178, 7, "F")
        pdf.set_xy(19, y)
        pdf.set_font("Plex", "", 9.5)
        pdf.set_text_color(*SLATE)
        pdf.cell(50, 7, clean(k))
        pdf.set_font("Plex", "B", 10)
        pdf.set_text_color(*NAVY)
        pdf.cell(0, 7, pdf.fit(v, 122), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.heading("What happened")
    pdf.para(d.get("detail") or "")
    if d["kind"] == "ai":
        pdf.heading("Why the AI flagged it")
        pdf.para("The AI learned what normal activity looks like on this connection, then compared this "
              f"{'user' if who.startswith('user:') else 'address'}'s last 30 seconds with it. These numbers were well above normal:")
        pdf.ln(1)
        pdf.bullets(d.get("why") or ["The overall mix of activity was very different from normal."])
        if d.get("score") is not None and d.get("threshold") is not None:
            pdf.ln(1)
            if d["score"] >= d["threshold"]:
                pdf.para(f"Isolation Forest unusualness score {d['score']:.3f}, above its alert line of {d['threshold']:.3f}.", 9, SLATE)
            else:
                pdf.para(f"Some numbers were far beyond anything seen while learning, which is enough on its own "
                         f"(Isolation Forest score {d['score']:.3f}, alert line {d['threshold']:.3f}).", 9, SLATE)
    else:
        pdf.heading("Why it was flagged")
        pdf.para("It matched a known attack pattern"
              + (f": {d['mitre']}." if d.get("mitre") else ".")
              + " Known patterns catch familiar attacks within seconds.")

    if story and story.get("reached"):
        pdf.heading("The attack story")
        pdf.para(f"{story['summary']} {story['verdict']}")
        pdf.ln(3)
        stages = story["stages"]
        w, gap, y = (178 - gap_total(len(stages))) / len(stages), 2.2, pdf.get_y()
        if y > 245:
            pdf.add_page()
            y = pdf.get_y()
        for i, s in enumerate(stages):
            xx = 16 + i * (w + gap)
            on = bool(s["alerts"])
            pdf.set_fill_color(*(NAVY if on else MIST))
            pdf.rect(xx, y, w, 19, "F")
            if on:
                pdf.set_fill_color(*BRASS)
                pdf.rect(xx, y, w, 1.6, "F")
            pdf.set_xy(xx + 1.5, y + 3)
            pdf.set_font("Plex", "B", 7.6)
            pdf.set_text_color(*((255, 255, 255) if on else SLATE))
            pdf.multi_cell(w - 3, 3.6, clean(s["name"]), align="L")
            pdf.set_xy(xx + 1.5, y + 13.2)
            pdf.set_font("Plex", "", 6.6)
            pdf.set_text_color(*((201, 212, 226) if on else (150, 162, 178)))
            pdf.cell(w - 3, 3.5, clean(f"{len(s['alerts'])} alert{'s' if len(s['alerts']) != 1 else ''}" if on else "not seen"))
        pdf.set_y(y + 22)
        pdf.para("Steps follow the MITRE ATT&CK tactics: " + ", ".join(s["tactic"] for s in stages) + ".", 8.5, SLATE)

    pdf.heading("What to do now")
    pdf.para(d.get("advice") or "")

    lines = d.get("lines") or []
    pdf.heading(f"The evidence: {len(lines)} log line{'s' if len(lines) != 1 else ''}" + (" (first 40 shown)" if len(lines) > 40 else ""))
    for ln in lines[:40]:
        if pdf.get_y() > 270:
            pdf.add_page()
        y = pdf.get_y()
        if ln.get("bad"):
            pdf.set_fill_color(251, 228, 223)
            pdf.rect(16, y, 178, 9.4, "F")
        pdf.set_xy(17.5, y + 0.6)
        pdf.set_font("Plex", "B", 8.6)
        pdf.set_text_color(*NAVY)
        pdf.cell(18, 4.2, clean(ln["time"]))
        pdf.set_font("Plex", "", 8.6)
        pdf.set_text_color(*BODY)
        pdf.cell(0, 4.2, pdf.fit(ln["plain"], 156), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_x(35.5)
        pdf.set_font("Mono", "", 6.8)
        pdf.set_text_color(*SLATE)
        pdf.cell(0, 4.2, pdf.fit(ln["raw"], 157), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_y(y + 10)
    if not lines:
        pdf.para("No log lines were kept for this alert.", 10, SLATE)
    return bytes(pdf.output())


def gap_total(n):
    return 2.2 * (n - 1)
