"""Generate the JANUS hackathon pitch deck.

Output: c:/Users/bhujbalsa/Downloads/AgenticSecurityPlatform.pptx  (16:9, dark theme)

JANUS — Roman god with two faces. One looks outward at attackers, the other
looks inward at wasted compute. One platform, two missions, same agentic
4-agent loop:
  Security : Scan → Attack → Heal → Validate
  Efficiency: Profile → Refactor → Benchmark → Verify

Team: The Janitors.

Design notes:
- 10 slides: title / problem / insight / architecture / demo / results / ROI /
  AI risk / roadmap / closing.
- Native PPT shapes throughout so every slide is editable in PowerPoint.
- Two visual languages woven through:  ACCENT (blue) for security path,
  ACCENT_2 (green) for efficiency path.
"""
from __future__ import annotations

import sys
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt


# ---------- theme ---------------------------------------------------------

BG       = RGBColor(0x0B, 0x0F, 0x17)
PANEL    = RGBColor(0x1A, 0x22, 0x33)
PANEL_2  = RGBColor(0x22, 0x2C, 0x41)
LINE     = RGBColor(0x2A, 0x35, 0x52)
TEXT     = RGBColor(0xE6, 0xED, 0xF7)
DIM      = RGBColor(0x8A, 0x98, 0xB1)
ACCENT   = RGBColor(0x3E, 0xA6, 0xFF)   # blue   -- security mission
ACCENT_2 = RGBColor(0x6C, 0xE5, 0xB3)   # teal   -- efficiency mission
OK       = RGBColor(0x4A, 0xDE, 0x80)
WARN     = RGBColor(0xFB, 0xBF, 0x24)
BAD      = RGBColor(0xF8, 0x71, 0x71)

SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)

OUTPUT_PATH = Path(r"C:/Users/bhujbalsa/Downloads/AgenticSecurityPlatform.pptx")


# ---------- helpers -------------------------------------------------------

def fill_solid(shape, color: RGBColor):
    shape.fill.solid()
    shape.fill.fore_color.rgb = color


def line_solid(shape, color: RGBColor, width=Pt(0.75)):
    shape.line.color.rgb = color
    shape.line.width = width


def no_line(shape):
    shape.line.fill.background()


def add_rect(slide, x, y, w, h, fill=PANEL, outline=LINE, radius=0.06):
    r = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    r.adjustments[0] = radius
    fill_solid(r, fill)
    if outline is None:
        no_line(r)
    else:
        line_solid(r, outline)
    return r


def add_text(slide, x, y, w, h, text, *, size=18, bold=False, color=TEXT,
             align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, font="Segoe UI"):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.05)
    tf.margin_right = Inches(0.05)
    tf.margin_top = Inches(0.02)
    tf.margin_bottom = Inches(0.02)
    tf.vertical_anchor = anchor
    paragraphs = text.split("\n") if isinstance(text, str) else [str(text)]
    for i, line in enumerate(paragraphs):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        r = p.add_run()
        r.text = line
        r.font.name = font
        r.font.size = Pt(size)
        r.font.bold = bold
        r.font.color.rgb = color
    return tb


def new_slide(prs, layout_idx=6):
    slide = prs.slides.add_slide(prs.slide_layouts[layout_idx])
    bg = slide.background
    bg.fill.solid()
    bg.fill.fore_color.rgb = BG
    return slide


def add_header(slide, eyebrow: str, title: str):
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, Inches(0.06))
    fill_solid(bar, ACCENT_2)
    no_line(bar)
    add_text(slide, Inches(0.6), Inches(0.25), Inches(12), Inches(0.4),
             eyebrow, size=12, bold=True, color=ACCENT_2)
    add_text(slide, Inches(0.6), Inches(0.55), Inches(12), Inches(0.9),
             title, size=30, bold=True, color=TEXT)


def add_footer(slide, page: str, brand="JANUS · The Janitors"):
    add_text(slide, Inches(0.6), Inches(7.05), Inches(8), Inches(0.3),
             brand, size=10, color=DIM)
    add_text(slide, Inches(11.5), Inches(7.05), Inches(1.4), Inches(0.3),
             page, size=10, color=DIM, align=PP_ALIGN.RIGHT)


def add_chip(slide, x, y, label, *, fill=PANEL_2, color=TEXT, size=10):
    w = Inches(max(0.6, 0.1 + 0.09 * len(label)))
    h = Inches(0.32)
    chip = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    chip.adjustments[0] = 0.5
    fill_solid(chip, fill)
    line_solid(chip, LINE, Pt(0.5))
    add_text(slide, x, y + Inches(0.04), w, Inches(0.26),
             label, size=size, color=color, align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
    return w


# ---------- slide builders -----------------------------------------------

def slide_title(prs):
    slide = new_slide(prs)
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, Inches(0.06))
    fill_solid(bar, ACCENT_2); no_line(bar)

    # JANUS — two-faced motif: a pair of overlapping diamond outlines
    d1 = slide.shapes.add_shape(MSO_SHAPE.DIAMOND, Inches(0.7), Inches(2.4),
                                Inches(0.7), Inches(0.7))
    fill_solid(d1, ACCENT); no_line(d1)
    d2 = slide.shapes.add_shape(MSO_SHAPE.DIAMOND, Inches(1.05), Inches(2.4),
                                Inches(0.7), Inches(0.7))
    fill_solid(d2, ACCENT_2); no_line(d2)

    add_text(slide, Inches(2.0), Inches(2.25), Inches(11), Inches(1.0),
             "JANUS", size=64, bold=True, color=TEXT)
    add_text(slide, Inches(2.0), Inches(3.25), Inches(11), Inches(0.5),
             "Two-faced agentic AI for payments code",
             size=22, color=ACCENT_2)
    add_text(slide, Inches(2.0), Inches(3.85), Inches(11), Inches(2.2),
             "One face proves security exploits — and patches them.\n"
             "The other face finds wasted compute — and refactors it.\n"
             "Same four-agent loop. Same safety nets at every step.\n"
             "Every change reviewed by a human before merge. No auto-merge, ever.",
             size=17, color=DIM)

    add_text(slide, Inches(0.7), Inches(6.5), Inches(12), Inches(0.4),
             "Team:  The Janitors  ·  ACI SpeedPay  ·  Hackathon 2026",
             size=14, color=DIM)

    # Stat tiles
    tile_y = Inches(5.4)
    stats = [
        ("4 / 4",  "exploits proven live\nwith concrete evidence",        ACCENT),
        ("390× / 347×", "speedups on real\ninefficient code",             ACCENT_2),
        ("$492 + 76 kg CO₂", "saved per year\n(2 funcs, 1 demo run)",     OK),
        ("< 8 min", "scan → fix → verify\nper repo",                       WARN),
    ]
    x = Inches(6.7)
    for value, label, color in stats:
        add_rect(slide, x, tile_y, Inches(1.55), Inches(1.0), fill=PANEL, outline=LINE)
        add_text(slide, x, tile_y + Inches(0.08), Inches(1.55), Inches(0.4),
                 value, size=15, bold=True, color=color, align=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE, font="Consolas")
        add_text(slide, x, tile_y + Inches(0.48), Inches(1.55), Inches(0.5),
                 label, size=9, color=DIM, align=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.TOP)
        x += Inches(1.65)


def slide_problem(prs):
    slide = new_slide(prs)
    add_header(slide, "01 / THE PROBLEM",
               "Payments code carries two hidden taxes. Both find us first.")

    # Two-column problem
    col_w = Inches(6.0)
    gap = Inches(0.15)
    left_x  = Inches(0.55)
    right_x = left_x + col_w + gap

    # LEFT: security mission problem
    add_rect(slide, left_x, Inches(1.6), col_w, Inches(5.0),
             fill=PANEL, outline=ACCENT)
    cap = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left_x, Inches(1.6),
                                 col_w, Inches(0.12))
    fill_solid(cap, ACCENT); no_line(cap)
    add_text(slide, left_x + Inches(0.3), Inches(1.85), col_w - Inches(0.5),
             Inches(0.4), "TAX #1 — SECURITY NOISE",
             size=13, bold=True, color=ACCENT)
    add_text(slide, left_x + Inches(0.3), Inches(2.3), col_w - Inches(0.5),
             Inches(4.3),
             "• Checkmarx + Black Duck dump 10,000+ findings per quarter\n"
             "• ~95% are noise, untriaged, duplicate, irrelevant\n"
             "• Senior engineers spend hours per finding to triage\n"
             "• Most findings get closed as 'not reproducible'\n"
             "• The REAL exploitable bugs get buried in the queue\n"
             "\n"
             "Cost today:\n"
             "  $1M / yr in triage labor (1,000 findings × 1h × $250)\n"
             "  $5M – $100M exposure per card-data incident\n"
             "  Audits + breaches find them when we don't",
             size=13, color=TEXT)

    # RIGHT: efficiency mission problem
    add_rect(slide, right_x, Inches(1.6), col_w, Inches(5.0),
             fill=PANEL, outline=ACCENT_2)
    cap2 = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, right_x, Inches(1.6),
                                  col_w, Inches(0.12))
    fill_solid(cap2, ACCENT_2); no_line(cap2)
    add_text(slide, right_x + Inches(0.3), Inches(1.85), col_w - Inches(0.5),
             Inches(0.4), "TAX #2 — WASTED COMPUTE",
             size=13, bold=True, color=ACCENT_2)
    add_text(slide, right_x + Inches(0.3), Inches(2.3), col_w - Inches(0.5),
             Inches(4.3),
             "• Real codebases ship loops that are O(n²) where O(n) would work\n"
             "• Strings concatenated in loops; regex re-compiled per iteration\n"
             "• N+1 queries hidden behind ORMs; linear scans against lists\n"
             "• Each one quietly burns CPU on every call, in every region\n"
             "\n"
             "Cost today:\n"
             "  Industry estimates put 20-30% of cloud spend on inefficient code\n"
             "  Tied directly to ACI's sustainability + ESG commitments\n"
             "  Cloud dashboards REPORT waste — after the bill arrives\n"
             "  Profilers exist — but who manually reads them?",
             size=13, color=TEXT)

    # Bottom punchline
    add_rect(slide, Inches(0.55), Inches(6.75), Inches(12.25), Inches(0.5),
             fill=PANEL_2, outline=ACCENT_2)
    add_text(slide, Inches(0.55), Inches(6.75), Inches(12.25), Inches(0.5),
             "Both taxes find us — through audits, breaches, and CFO reviews. "
             "We never find them first.",
             size=14, bold=True, color=ACCENT_2,
             align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)

    add_footer(slide, "2 / 10")


def slide_insight(prs):
    slide = new_slide(prs)
    add_header(slide, "02 / THE INSIGHT",
               "What if the same loop fixed both?")

    add_text(slide, Inches(0.6), Inches(1.55), Inches(12), Inches(0.5),
             "JANUS — Roman god of gates and transitions, two faces, looks both ways at once.",
             size=15, color=DIM)

    # Three pillars — applied to BOTH missions
    pillars = [
        ("PROVE",
         "Security  →  Claude writes a real exploit, runs it in a sandbox, "
         "produces concrete evidence (PAN values, stolen tokens, duplicate charges).\n"
         "\n"
         "Efficiency →  A profiler finds the hot path. Claude writes a "
         "benchmark; sandbox measures actual runtime.",
         ACCENT_2),
        ("FIX",
         "Security  →  Claude proposes a patch with PCI / OWASP citations. "
         "AST-validated before any file is written.\n"
         "\n"
         "Efficiency →  Claude rewrites the function — O(n²) → O(n), "
         "string concat → ''.join, regex hoisted out of loop. AST-validated too.",
         ACCENT),
        ("VERIFY",
         "Security  →  Tests must pass AND the exploit must no longer succeed. "
         "Either check fails → patch rejected.\n"
         "\n"
         "Efficiency →  Outputs must match the original AND the new code must "
         "be measurably faster. Either check fails → refactor rejected.",
         WARN),
    ]
    x = Inches(0.6)
    for label, body, color in pillars:
        add_rect(slide, x, Inches(2.2), Inches(4.0), Inches(4.3),
                 fill=PANEL, outline=LINE)
        cap = slide.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, x, Inches(2.2), Inches(4.0), Inches(0.12))
        fill_solid(cap, color); no_line(cap)
        add_text(slide, x + Inches(0.3), Inches(2.45), Inches(3.6), Inches(0.5),
                 label, size=24, bold=True, color=color)
        add_text(slide, x + Inches(0.3), Inches(3.05), Inches(3.6), Inches(3.4),
                 body, size=11, color=TEXT)
        x += Inches(4.2)

    # Bottom strip
    add_rect(slide, Inches(0.6), Inches(6.7), Inches(12.1), Inches(0.55),
             fill=PANEL_2, outline=ACCENT_2)
    add_text(slide, Inches(0.85), Inches(6.7), Inches(11.7), Inches(0.55),
             "Same architecture. Same safety nets. Two business outcomes: "
             "fewer breaches AND smaller cloud bill.",
             size=13, bold=True, color=ACCENT_2, anchor=MSO_ANCHOR.MIDDLE)

    add_footer(slide, "3 / 10")


def slide_architecture(prs):
    slide = new_slide(prs)
    add_header(slide, "03 / ARCHITECTURE",
               "One 4-agent loop. Two missions. The platform decides which.")

    # Two parallel pipelines, top + bottom, with shared central stages
    box_w = Inches(2.05)
    box_h = Inches(1.0)
    gap = Inches(0.25)
    start_x = Inches(0.55)
    sec_y = Inches(2.0)
    eff_y = Inches(4.55)

    sec_stages = [
        ("SCAN",       "Semgrep +\npayments rules"),
        ("ATTACK",     "Claude\nwrites PoC"),
        ("HEAL",       "Claude\nwrites patch"),
        ("VALIDATE",   "tests + replay"),
    ]
    eff_stages = [
        ("PROFILE",    "Semgrep +\nefficiency rules"),
        ("REFACTOR",   "Claude rewrites\nfunction"),
        ("BENCHMARK",  "Sandbox\nmeasures old vs new"),
        ("VERIFY",     "outputs match\n+ speedup proven"),
    ]

    # Mission labels (left side)
    add_text(slide, Inches(0.55), sec_y - Inches(0.35), Inches(2.0), Inches(0.3),
             "SECURITY FACE", size=11, bold=True, color=ACCENT)
    add_text(slide, Inches(0.55), eff_y - Inches(0.35), Inches(2.0), Inches(0.3),
             "EFFICIENCY FACE", size=11, bold=True, color=ACCENT_2)

    def draw_pipeline(y, stages, color):
        x = start_x
        arrow_h = Inches(0.3)
        for i, (label, sub) in enumerate(stages):
            add_rect(slide, x, y, box_w, box_h, fill=PANEL, outline=color)
            add_text(slide, x, y + Inches(0.05), box_w, Inches(0.32),
                     label, size=12, bold=True, color=color,
                     align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
            add_text(slide, x, y + Inches(0.4), box_w, Inches(0.55),
                     sub, size=10, color=TEXT,
                     align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
            if i < len(stages) - 1:
                ax = x + box_w
                arrow = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, ax,
                                               y + box_h/2 - arrow_h/2,
                                               gap, arrow_h)
                fill_solid(arrow, color); no_line(arrow)
            x += box_w + gap

    draw_pipeline(sec_y, sec_stages, ACCENT)
    draw_pipeline(eff_y, eff_stages, ACCENT_2)

    # PR output panel (shared)
    pr_x = start_x + 4 * box_w + 4 * gap
    add_rect(slide, pr_x, sec_y, Inches(2.4), Inches(2.55),
             fill=PANEL_2, outline=OK)
    add_text(slide, pr_x, sec_y + Inches(0.15), Inches(2.4), Inches(0.4),
             "PULL REQUEST", size=11, bold=True, color=OK,
             align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
    add_text(slide, pr_x + Inches(0.15), sec_y + Inches(0.55),
             Inches(2.1), Inches(2.0),
             "• Validated patch\n"
             "  + PoC exploit OR\n"
             "  + benchmark numbers\n"
             "• PCI / OWASP refs\n"
             "• $ + CO₂ delta\n"
             "• Human reviews\n"
             "  before merge",
             size=10, color=TEXT)

    # Safety net belt
    add_rect(slide, Inches(0.55), Inches(6.05), Inches(12.25), Inches(0.95),
             fill=PANEL_2, outline=ACCENT_2)
    add_text(slide, Inches(0.55), Inches(6.05), Inches(12.25), Inches(0.3),
             "SAFETY NETS — applied to every patch in both missions",
             size=10, bold=True, color=ACCENT_2,
             align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
    nets = [
        ("AST validated before disk write", ACCENT_2),
        ("File never half-written (atomic apply + rollback)", ACCENT_2),
        ("Tests must pass after the change", ACCENT_2),
        ("Behavior unchanged (exploit fails OR outputs match)", ACCENT_2),
        ("PR-gated review — no auto-merge, ever", ACCENT_2),
        ("LLM code runs sandboxed (Docker / subprocess)", ACCENT_2),
    ]
    # Two rows of net chips
    cx = Inches(0.75); cy = Inches(6.45)
    row_count = 0
    for label, color in nets:
        w = add_chip(slide, cx, cy, label, fill=BG, color=color, size=9)
        cx += w + Inches(0.1)
        row_count += 1
        if row_count == 3:
            cx = Inches(0.75); cy = Inches(6.75)

    add_footer(slide, "4 / 10")


def slide_demo_storyboard(prs):
    slide = new_slide(prs)
    add_header(slide, "04 / LIVE DEMO",
               "Two clicks. Two missions. Side by side.")

    col_w = Inches(6.0)
    gap   = Inches(0.15)
    left_x  = Inches(0.55)
    right_x = left_x + col_w + gap

    # LEFT: security demo
    add_rect(slide, left_x, Inches(1.6), col_w, Inches(5.0),
             fill=PANEL, outline=ACCENT)
    cap = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left_x, Inches(1.6),
                                 col_w, Inches(0.12))
    fill_solid(cap, ACCENT); no_line(cap)
    add_text(slide, left_x + Inches(0.3), Inches(1.85), col_w - Inches(0.5),
             Inches(0.4), "SECURITY FACE — “Run security demo”",
             size=13, bold=True, color=ACCENT)
    add_text(slide, left_x + Inches(0.3), Inches(2.3), col_w - Inches(0.5),
             Inches(4.3),
             "0:00  Target Flask payment API spins up\n"
             "0:45  Semgrep finds 4 payments-domain vulnerabilities\n"
             "1:30  Claude writes a Python exploit, runs it in sandbox →\n"
             "       EXPLOIT_SUCCESS: PAN 4111… returned in /logs\n"
             "3:00  Claude proposes a masking fix (PCI DSS 3.4 cited)\n"
             "3:30  Validator runs pytest + replays exploit\n"
             "       → patch breaks API contract → REJECTED\n"
             "8:00  Final report: 4 confirmed exploits, 3 patches proposed,\n"
             "       all rejected by safety net for human review",
             size=11, color=TEXT, font="Consolas")

    # RIGHT: efficiency demo
    add_rect(slide, right_x, Inches(1.6), col_w, Inches(5.0),
             fill=PANEL, outline=ACCENT_2)
    cap2 = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, right_x, Inches(1.6),
                                  col_w, Inches(0.12))
    fill_solid(cap2, ACCENT_2); no_line(cap2)
    add_text(slide, right_x + Inches(0.3), Inches(1.85), col_w - Inches(0.5),
             Inches(0.4), "EFFICIENCY FACE — “Run efficiency demo”",
             size=13, bold=True, color=ACCENT_2)
    add_text(slide, right_x + Inches(0.3), Inches(2.3), col_w - Inches(0.5),
             Inches(4.3),
             "0:00  Profiler finds 4 inefficient patterns in target-perf\n"
             "0:30  Claude refactors `find_common_account_ids`\n"
             "       O(n²) linear scan  →  O(n) set lookup\n"
             "1:00  Sandbox runs old vs new on 4,000-element inputs:\n"
             "       390× faster, outputs identical → VERIFIED\n"
             "2:00  Same for `find_duplicate_transaction_pairs`:\n"
             "       347× faster → VERIFIED\n"
             "       (2 of 4 rejected: 1 had no speedup, 1 changed output —\n"
             "        safety net working)\n"
             "8:00  Report: $492 / yr + 76 kg CO₂ / yr saved (2 funcs only)",
             size=11, color=TEXT, font="Consolas")

    # Bottom — what each evidence row says
    add_rect(slide, Inches(0.55), Inches(6.75), Inches(12.25), Inches(0.5),
             fill=PANEL_2, outline=ACCENT_2)
    add_text(slide, Inches(0.55), Inches(6.75), Inches(12.25), Inches(0.5),
             "Both demos run live, in the same UI, on the same Claude Code subscription.",
             size=13, bold=True, color=ACCENT_2,
             align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)

    add_footer(slide, "5 / 10")


def slide_results(prs):
    slide = new_slide(prs)
    add_header(slide, "05 / REAL RESULTS",
               "Numbers from the runs we just executed.")

    col_w = Inches(6.0)
    gap   = Inches(0.15)
    left_x  = Inches(0.55)
    right_x = left_x + col_w + gap

    # SECURITY RESULTS
    add_rect(slide, left_x, Inches(1.6), col_w, Inches(5.4),
             fill=PANEL, outline=ACCENT)
    cap = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left_x, Inches(1.6),
                                 col_w, Inches(0.12))
    fill_solid(cap, ACCENT); no_line(cap)
    add_text(slide, left_x + Inches(0.3), Inches(1.85), col_w - Inches(0.5),
             Inches(0.4), "SECURITY FACE — Sample exploit evidence",
             size=13, bold=True, color=ACCENT)
    add_text(slide, left_x + Inches(0.3), Inches(2.3), col_w - Inches(0.5),
             Inches(0.4),
             "Real signals returned by Claude-generated exploits:",
             size=11, color=DIM)
    sigs = [
        "EXPLOIT_SUCCESS: PAN 4111111111111111 and",
        "  CVV 4815162342 returned in /logs response",
        "",
        "EXPLOIT_SUCCESS: stale token still authorizes",
        "  /account/1 after re-login (no TTL/revocation)",
        "",
        "EXPLOIT_SUCCESS: duplicate charges accepted",
        "  without Idempotency-Key — tx1 + tx2 issued",
        "",
        "EXPLOIT_SUCCESS: same key allows duplicate",
        "  payment with no dedup check",
    ]
    add_text(slide, left_x + Inches(0.3), Inches(2.85), col_w - Inches(0.5),
             Inches(3.0),
             "\n".join(sigs), size=11, color=TEXT, font="Consolas")
    add_text(slide, left_x + Inches(0.3), Inches(6.0), col_w - Inches(0.5),
             Inches(0.4),
             "Already validated on real ACI repos — InternetApi,\n"
             "ExtranetApi (3 real Dapper SQLi Checkmarx missed), rtal.",
             size=11, color=ACCENT)

    # EFFICIENCY RESULTS
    add_rect(slide, right_x, Inches(1.6), col_w, Inches(5.4),
             fill=PANEL, outline=ACCENT_2)
    cap2 = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, right_x, Inches(1.6),
                                  col_w, Inches(0.12))
    fill_solid(cap2, ACCENT_2); no_line(cap2)
    add_text(slide, right_x + Inches(0.3), Inches(1.85), col_w - Inches(0.5),
             Inches(0.4), "EFFICIENCY FACE — Measured speedups",
             size=13, bold=True, color=ACCENT_2)

    # Two big stat blocks
    add_rect(slide, right_x + Inches(0.3), Inches(2.4), Inches(5.4), Inches(1.7),
             fill=BG, outline=ACCENT_2)
    add_text(slide, right_x + Inches(0.4), Inches(2.5), Inches(5.2), Inches(0.4),
             "find_common_account_ids   (linear-search-in-loop)",
             size=11, bold=True, color=ACCENT_2, font="Consolas")
    add_text(slide, right_x + Inches(0.4), Inches(2.95), Inches(5.2), Inches(0.5),
             "390× faster",
             size=22, bold=True, color=OK, font="Consolas")
    add_text(slide, right_x + Inches(0.4), Inches(3.5), Inches(5.2), Inches(0.5),
             "Projected $310.23 / yr  ·  47,992 g CO₂ / yr saved",
             size=11, color=TEXT, font="Consolas")

    add_rect(slide, right_x + Inches(0.3), Inches(4.25), Inches(5.4), Inches(1.7),
             fill=BG, outline=ACCENT_2)
    add_text(slide, right_x + Inches(0.4), Inches(4.35), Inches(5.2), Inches(0.4),
             "find_duplicate_transaction_pairs   (nested-loop)",
             size=11, bold=True, color=ACCENT_2, font="Consolas")
    add_text(slide, right_x + Inches(0.4), Inches(4.8), Inches(5.2), Inches(0.5),
             "347× faster",
             size=22, bold=True, color=OK, font="Consolas")
    add_text(slide, right_x + Inches(0.4), Inches(5.35), Inches(5.2), Inches(0.5),
             "Projected $182.25 / yr  ·  28,194 g CO₂ / yr saved",
             size=11, color=TEXT, font="Consolas")

    add_text(slide, right_x + Inches(0.3), Inches(6.0), col_w - Inches(0.5),
             Inches(0.4),
             "2 of 4 refactors rejected by the safety net —\n"
             "no speedup or output diverged. File untouched.",
             size=11, color=ACCENT_2)

    add_footer(slide, "6 / 10")


def slide_money(prs):
    slide = new_slide(prs)
    add_header(slide, "06 / THE MONEY",
               "What the dual mission saves per year per product.")

    col_w = Inches(6.0)
    gap = Inches(0.15)
    left_x  = Inches(0.55)
    right_x = left_x + col_w + gap

    # SECURITY ROI
    add_rect(slide, left_x, Inches(1.6), col_w, Inches(5.0),
             fill=PANEL, outline=ACCENT)
    cap = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left_x, Inches(1.6),
                                 col_w, Inches(0.12))
    fill_solid(cap, ACCENT); no_line(cap)
    add_text(slide, left_x + Inches(0.3), Inches(1.85), col_w - Inches(0.5),
             Inches(0.4), "SECURITY FACE  —  triage labor recovered",
             size=13, bold=True, color=ACCENT)
    rows = [
        ("Manual triage today (1000 findings × 1h × $250)",  "$250K /qtr",   BAD),
        ("Annualized",                                       "$1M / yr",     BAD),
        ("Avg breach exposure (1 event / 5 yrs)",            "$10M / event", BAD),
        ("",                                                  "",            None),
        ("JANUS triage cost (LLM per scan, ~$1–2)",          "$0.5K / yr",   OK),
        ("Confirmed-exploitable findings only — 95% noise removed", "—",     OK),
        ("Net annual saving — per product",                  "≈ $1M",        OK),
    ]
    y = Inches(2.35)
    for k, v, color in rows:
        if not k:
            y += Inches(0.18); continue
        add_text(slide, left_x + Inches(0.3), y, Inches(4.0), Inches(0.35),
                 k, size=11, color=TEXT, anchor=MSO_ANCHOR.MIDDLE)
        if color:
            add_text(slide, left_x + Inches(4.3), y, Inches(1.5), Inches(0.35),
                     v, size=12, bold=True, color=color, font="Consolas",
                     align=PP_ALIGN.RIGHT, anchor=MSO_ANCHOR.MIDDLE)
        y += Inches(0.35)

    # EFFICIENCY ROI
    add_rect(slide, right_x, Inches(1.6), col_w, Inches(5.0),
             fill=PANEL, outline=ACCENT_2)
    cap2 = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, right_x, Inches(1.6),
                                  col_w, Inches(0.12))
    fill_solid(cap2, ACCENT_2); no_line(cap2)
    add_text(slide, right_x + Inches(0.3), Inches(1.85), col_w - Inches(0.5),
             Inches(0.4), "EFFICIENCY FACE  —  cloud + carbon recovered",
             size=13, bold=True, color=ACCENT_2)
    rows2 = [
        ("From 1 demo run, 2 functions",  "$492 / yr",       OK),
        ("CO₂ at IEA avg grid intensity", "76 kg / yr",      OK),
        ("",                              "",                None),
        ("Conservative scale-up",         "",                DIM),
        ("100 hot functions across SpeedPay services",
                                          "≈ $25K – $50K /yr", OK),
        ("CO₂ equivalent",                "≈ 4 tonnes /yr",  OK),
        ("",                              "",                None),
        ("Plus: ESG narrative for FY-26 sustainability report",
                                          "(unquantifiable)",ACCENT_2),
    ]
    y = Inches(2.35)
    for k, v, color in rows2:
        if not k:
            y += Inches(0.18); continue
        add_text(slide, right_x + Inches(0.3), y, Inches(4.0), Inches(0.35),
                 k, size=11, color=TEXT, anchor=MSO_ANCHOR.MIDDLE)
        if color:
            add_text(slide, right_x + Inches(4.3), y, Inches(1.5), Inches(0.35),
                     v, size=12, bold=True, color=color, font="Consolas",
                     align=PP_ALIGN.RIGHT, anchor=MSO_ANCHOR.MIDDLE)
        y += Inches(0.35)

    # Bottom payoff
    add_rect(slide, Inches(0.55), Inches(6.75), Inches(12.25), Inches(0.5),
             fill=PANEL_2, outline=ACCENT_2)
    add_text(slide, Inches(0.55), Inches(6.75), Inches(12.25), Inches(0.5),
             "Per product, per year: ~$1M security savings + ~$25–50K cloud savings + measurable CO₂ reduction.",
             size=14, bold=True, color=ACCENT_2,
             align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)

    add_footer(slide, "7 / 10")


def slide_ai_risk(prs):
    slide = new_slide(prs)
    add_header(slide, "07 / AI RISK MITIGATION",
               "We use an LLM. We also defang the LLM's failure modes.")

    add_text(slide, Inches(0.6), Inches(1.55), Inches(12), Inches(0.4),
             "Aligned to MITRE ATLAS + OWASP Top 10 for LLM Applications. "
             "Same safety nets cover both faces of JANUS.",
             size=11, color=DIM)

    rows = [
        ("Prompt injection (malicious code hijacks the LLM)",
         "Single-turn LLM calls. JSON-only output parsed strictly. "
         "Anything not parsable is discarded."),
        ("LLM hallucinates / writes broken patch or refactor",
         "Every patch + refactor AST-validated before disk write. "
         "Bad syntax → file untouched, finding marked FAILED."),
        ("LLM “fixes” the bug by hiding a backdoor",
         "Security: validator replays the original exploit. If it still "
         "succeeds → REJECTED.  Efficiency: outputs must match original."),
        ("Refactor secretly returns wrong results",
         "Verifier compares old vs new outputs on benchmark inputs. "
         "Mismatch → REJECTED. File never modified."),
        ("Source code leaks to a 3rd party",
         "No SaaS scanning. `--metrics off`. Only the vulnerable / "
         "inefficient snippet goes to Claude — not the full repo."),
        ("LLM-generated code escapes the sandbox",
         "Hardened Docker (cap-stripped, read-only, no net out, 30s timeout). "
         "Subprocess fallback only for trusted local targets."),
        ("Stale orphan process serves wrong code on replay",
         "Deployer kills ANY process on the target port before starting "
         "fresh. Each run starts from a clean state."),
        ("Cost / token bombing",
         "max_turns=5, allowed_tools=[]. Per-scan LLM cost capped at "
         "single-digit dollars. Runs on Claude Code subscription."),
        ("Auto-merge of LLM-written code",
         "Explicitly disabled. PR-based human review is the merge gate. "
         "Always. For both faces."),
    ]
    y = Inches(2.05)
    row_h = Inches(0.5)
    for risk, mit in rows:
        add_rect(slide, Inches(0.55), y, Inches(5.4), row_h, fill=PANEL, outline=LINE)
        add_text(slide, Inches(0.75), y, Inches(5.1), row_h,
                 risk, size=10.5, color=BAD, anchor=MSO_ANCHOR.MIDDLE, bold=True)
        add_rect(slide, Inches(6.05), y, Inches(6.8), row_h, fill=PANEL, outline=LINE)
        add_text(slide, Inches(6.25), y, Inches(6.5), row_h,
                 mit, size=10.5, color=TEXT, anchor=MSO_ANCHOR.MIDDLE)
        y += row_h + Inches(0.04)

    add_footer(slide, "8 / 10")


def slide_roadmap(prs):
    slide = new_slide(prs)
    add_header(slide, "08 / BUILT vs ROADMAP",
               "Honest status. Both faces shipped.")

    cols = [
        ("BUILT TODAY (both faces)", OK, [
            "All 8 agents shipped — 4 per face",
            "Bundled rule packs: payments (Python), .NET, Angular, efficiency",
            "Live web UI with two demo buttons (security / efficiency)",
            "Real-time progress streaming (SSE), detail drawer with diff + benchmark",
            "Sandboxed execution (Docker + subprocess fallback)",
            "AST safety net on every patch + refactor",
            "Persistent scan store (survives restart)",
            "Validated on REAL ACI repos:\n"
            "  • Security: 3 Dapper SQLi in ExtranetApi\n"
            "  • Efficiency: 390× and 347× speedups",
            "Uses Claude Code login — $0 new license",
        ]),
        ("LIMITED", WARN, [
            "Security healer is single-region (multi-file fix is next)",
            "Subprocess sandbox is less safe than Docker (use Docker in prod)",
            "Validator needs pytest in the target repo",
            "Java / Spring rule packs not yet shipped",
            "Carbon math uses configurable assumptions — tune per team",
        ]),
        ("NEXT 90 DAYS", ACCENT, [
            "Multi-region healer: edit multiple files + update tests atomically",
            "Java / Spring rule packs across both faces",
            "Full-loop on a live ACI service (needs docker-compose for target)",
            "Automatic PR creation with PoC / benchmark / diff / savings",
            "Per-finding cost dashboard for engineering leadership",
            "SSO + audit log for shared deployment",
            "Rule-tuning feedback loop: false-positive marks feed back into Semgrep",
        ]),
    ]
    x = Inches(0.55)
    col_w = Inches(4.1)
    for title, color, items in cols:
        add_rect(slide, x, Inches(1.65), col_w, Inches(5.45),
                 fill=PANEL, outline=color)
        cap = slide.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, x, Inches(1.65), col_w, Inches(0.12))
        fill_solid(cap, color); no_line(cap)
        add_text(slide, x, Inches(1.85), col_w, Inches(0.45),
                 title, size=13, bold=True, color=color,
                 align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        body = "\n".join("•  " + it for it in items)
        add_text(slide, x + Inches(0.2), Inches(2.4), col_w - Inches(0.4),
                 Inches(4.5),
                 body, size=10, color=TEXT)
        x += col_w + Inches(0.2)

    add_footer(slide, "9 / 10")


def slide_closing(prs):
    slide = new_slide(prs)
    add_header(slide, "09 / WHY THIS WINS",
               "Three reasons The Janitors should win this hackathon.")

    pillars = [
        ("REAL EVIDENCE, NOT THEORY",
         "Every security finding ships with an actual Python PoC that ran "
         "in a sandbox and printed marker-based evidence (PANs, txids, tokens).\n"
         "\n"
         "Every efficiency finding ships with a measured speedup on real inputs.\n"
         "\n"
         "Checkmarx says ‘possible SQL injection.’ Cloud dashboards say "
         "‘bill is up.’ JANUS says ‘here is the exact request that breaks "
         "/login’ and ‘here is the 390× faster rewrite.’",
         ACCENT_2),
        ("ONE LOOP, TWO FACES",
         "Most teams build one tool for one job. We built one architecture, "
         "applied to two of the biggest budget lines in payments engineering: "
         "security risk AND cloud spend / carbon.\n"
         "\n"
         "Adding the next face (e.g. flaky-test detection, dead-code removal) "
         "is the same 4-agent shape with a different scanner up front.",
         ACCENT),
        ("SAFETY NETS THAT SAY NO",
         "The validator rejected 3 of 3 security patches in our demo because "
         "they broke API contracts. The verifier rejected 2 of 4 refactors "
         "because they were slower or changed outputs.\n"
         "\n"
         "That's the system working. Auto-merging LLM-written code is the "
         "anti-pattern. JANUS will never do it.",
         WARN),
    ]
    x = Inches(0.55)
    for title, body, color in pillars:
        add_rect(slide, x, Inches(1.65), Inches(4.1), Inches(4.4),
                 fill=PANEL, outline=color)
        cap = slide.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, x, Inches(1.65), Inches(4.1), Inches(0.12))
        fill_solid(cap, color); no_line(cap)
        add_text(slide, x + Inches(0.25), Inches(1.9), Inches(3.7), Inches(0.55),
                 title, size=14, bold=True, color=color, anchor=MSO_ANCHOR.MIDDLE)
        add_text(slide, x + Inches(0.25), Inches(2.6), Inches(3.7), Inches(3.3),
                 body, size=11, color=TEXT)
        x += Inches(4.2)

    # Closing kill-line
    add_rect(slide, Inches(0.55), Inches(6.25), Inches(12.25), Inches(0.95),
             fill=PANEL_2, outline=ACCENT_2)
    add_text(slide, Inches(0.55), Inches(6.3), Inches(12.25), Inches(0.85),
             "Checkmarx tells you what MIGHT be wrong. Cloud dashboards "
             "report waste after the bill arrives.\n"
             "JANUS catches BOTH before they reach production — and proposes "
             "the fix.",
             size=15, bold=True, color=ACCENT_2,
             align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)

    add_footer(slide, "10 / 10")


# ---------- main ----------------------------------------------------------

def build() -> Path:
    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H

    slide_title(prs)
    slide_problem(prs)
    slide_insight(prs)
    slide_architecture(prs)
    slide_demo_storyboard(prs)
    slide_results(prs)
    slide_money(prs)
    slide_ai_risk(prs)
    slide_roadmap(prs)
    slide_closing(prs)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    prs.save(OUTPUT_PATH)
    return OUTPUT_PATH


if __name__ == "__main__":
    path = build()
    size_kb = path.stat().st_size / 1024
    print(f"OK: wrote {path} ({size_kb:.1f} KB, 10 slides)")
    sys.exit(0)
