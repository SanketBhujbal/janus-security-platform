"""Build the Agentic Security Platform pitch in ACI Hackathon 2026 template.

Strategy: copy the official template (which has full-bleed background images,
logos, decorative side panels, etc.) and replace ONLY the text content. All
images, layouts, branding, and shape positions stay intact -- we're just
swapping the words in the existing text boxes.

This guarantees the output matches the format the judges expect, regardless
of corporate styling we don't have visibility into.

Output: C:/Users/bhujbalsa/Downloads/AgenticSecurityPlatform_AciTemplate.pptx
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Iterable

from pptx import Presentation
from pptx.util import Pt


TEMPLATE = Path(r"C:/Users/bhujbalsa/Downloads/Stormbreakers - Hackathon 2026 demo for judging.pptx")
OUTPUT   = Path(r"C:/Users/bhujbalsa/Downloads/AgenticSecurityPlatform_AciTemplate.pptx")


# ---------- our content, mapped to the template's 12-slide flow ----------
#
# Template flow (preserved):
#   1. Title          (Region / Project / Team)
#   2. Meet the Team
#   3. The "Why?"
#   4. <Pain heartburn>
#   5. <How it's done today>
#   6. <Result of today's approach>  (one BIG sentence)
#   7. <Technical Showcase>
#   8. <Showcase Result>             (one BIG sentence)
#   9. <A New Standard>              (benefits)
#  10. <What Next?>                  (roadmap)
#  11. <Key Takeaways>               (3-4 punchy lines)
#  12. <Closing>                     (image only - no text)
#
# Each entry is {slide_idx: {"title": "...", "body": [..lines..]}}.
# title=None means don't change the title; body=None means don't change body.

CONTENT = {
    1: {
        "Americas":                                    "Americas",
        "BASE24 Migration Enablement Using AI":        "Agentic Security Platform",
        "The Stormbreakers":                           "[ Your Team Name ]",
    },
    2: {
        "title": "Meet the Team!",
        "body": [
            "[ Your Team Name ]",
            "",
            "Sanket Bhujbal — Software Engineer (SpeedPay)",
            "[ Team Member 2 — Role ]",
            "[ Team Member 3 — Role ]",
            "[ Team Member 4 — Role ]",
        ],
    },
    3: {
        "title": "The “Why?”",
        "body": [
            "Risk to ACI",
            "Every SpeedPay product ships with thousands of unverified Checkmarx + Black Duck findings",
            "~95% are noise; the few real exploitable bugs get buried",
            "Engineers tune the tools out. PCI auditors don't.",
            "",
            "Cost today",
            "$1M / yr in senior triage labor on findings nobody fixes",
            "$5M – $100M exposure per card-data incident",
            "And the LLMs the attackers use are getting cheaper than ours",
            "",
            "A new way?",
            "What if SAST could PROVE the bug AND propose the fix?",
        ],
    },
    4: {
        "title": "Security Heartburn",
        "body": [
            "To date:",
            "Checkmarx + Black Duck report theoretical findings, not exploitable ones",
            "Senior security engineers spend hours per finding to triage",
            "Most findings get closed as “not reproducible” — but were they really?",
            "The few real exploits are buried under noise; audits and incidents catch what we missed",
            "",
            "A new way? Can agentic AI help?",
            "Have an LLM write the actual PoC — and run it in a sandbox",
            "Have a second LLM propose the patch",
            "Have a third agent VALIDATE the patch defeats the exploit AND keeps tests green",
            "No auto-merge. Always a human reviewer at the PR.",
        ],
    },
    5: {
        "title": "Today’s Security Workflow",
        "body": [
            "Checkmarx / Black Duck scan",
            "10,000+ findings dumped into a backlog",
            "Triage queue",
            "  Senior engineer reads each finding manually",
            "  Decides if it’s real",
            "  Writes a Jira ticket",
            "  Assigns to a developer who hasn’t seen the code in months",
            "",
            "Assumes:",
            "  Engineers will read every finding (they won’t)",
            "  Findings include enough context to fix (they don’t)",
            "  A patch will be written + reviewed + merged (sometimes, eventually)",
        ],
    },
    6: {
        "title": "Today’s Security Result?",
        "body": [
            "Backlog of 10,000 findings. ~$1M / yr in triage. And we still miss the real exploits.",
            "",
            "And the audit catches them for us.",
        ],
    },
    7: {
        "title": "Technical Showcase",
        "body": [
            "We built an Agentic Security Platform — four LLM agents in a loop:",
            "",
            "  1. Scanner   — Semgrep + payments-domain rules (Python / .NET / Angular)",
            "  2. Attacker  — Claude writes a Python PoC and runs it in a sandbox",
            "  3. Healer    — Claude proposes a patch; AST-validated before disk write",
            "  4. Validator — Tests must pass AND original exploit must no longer succeed",
            "",
            "Live UI streams every step. Real exploits with concrete evidence:",
            "  “EXPLOIT_SUCCESS: PAN 4111... returned in /logs”",
            "  “EXPLOIT_SUCCESS: stale token still authorizes /account/1”",
            "  “EXPLOIT_SUCCESS: duplicate charges with same Idempotency-Key”",
            "",
            "Auth: Claude Agent SDK (uses your Claude Code login — no extra API key).",
            "Already de-noised on real ACI repos: InternetApi, ExtranetApi, rtal.",
        ],
    },
    8: {
        "title": "Our Result?",
        "body": [
            "~8 minutes from scan to validated patch. ~$1 in compute. Real exploits proven, real fixes proposed.",
            "",
            "And every patch is human-reviewed before merge.",
        ],
    },
    9: {
        "title": "A New Standard",
        "body": [
            "Benefits",
            "  Real exploits, not theoretical findings",
            "  Concrete evidence (marker PAN values, txids, stale tokens) the audit team will love",
            "  Proposed patches with PCI / OWASP citations the developer can act on immediately",
            "  Validator catches contract-breaking patches BEFORE they reach main",
            "",
            "Differentiators vs Checkmarx + Black Duck",
            "  They report. We act.",
            "  They miss exploits. We prove them.",
            "  They produce noise. We produce PRs.",
            "",
            "Designed for ACI",
            "  Rules tuned to SpeedPay’s actual stack: Dapper SQL, ContextIdentity auth, ngx-webstorage",
            "  Runs behind your corporate TLS proxy — source code never leaves the host",
        ],
    },
    10: {
        "title": "What’s Next?",
        "body": [
            "Multi-region patching — let the healer edit multiple files at once + update tests",
            "Java / Spring rule pack (alongside Python / .NET / Angular today)",
            "Full-loop demo on a live ACI service (needs docker-compose for the target)",
            "PR auto-creation with PoC + before/after diff + LLM explanation",
            "AI-risk hardening continued: MITRE ATLAS coverage, prompt-injection red team",
            "Cost / metrics dashboard for security leadership",
            "Shared deployment with SSO + audit log",
        ],
    },
    11: {
        "title": "Key Takeaways",
        "body": [
            "Checkmarx tells you what MIGHT be wrong. This tells you what an attacker WILL do.",
            "",
            "Real exploits, real patches, real safety nets — built on the Claude Code subscription you already pay for.",
            "",
            "~$1M / yr of triage labor recovered per product, with order-of-magnitude better signal.",
        ],
    },
    # Slide 12 is the closing image — leave untouched.
}


# ---------- text-frame helpers --------------------------------------------

def _capture_first_run_format(tf):
    """Save the FIRST RUN's typeface so we can re-apply when we rewrite text."""
    for para in tf.paragraphs:
        for run in para.runs:
            font = run.font
            try:
                color_rgb = font.color.rgb if font.color and font.color.type is not None else None
            except Exception:
                color_rgb = None
            return {
                "name": font.name,
                "size": font.size,
                "bold": font.bold,
                "italic": font.italic,
                "color_rgb": color_rgb,
            }
    return {}


def _apply_format(run, fmt):
    if fmt.get("name"):
        run.font.name = fmt["name"]
    if fmt.get("size"):
        run.font.size = fmt["size"]
    if fmt.get("bold") is not None:
        run.font.bold = fmt["bold"]
    if fmt.get("italic") is not None:
        run.font.italic = fmt["italic"]
    if fmt.get("color_rgb") is not None:
        run.font.color.rgb = fmt["color_rgb"]


def replace_textframe(tf, lines):
    """Replace tf contents with `lines` (list of strings). Preserves the
    first-run typography so the slide still looks on-brand."""
    fmt = _capture_first_run_format(tf)
    tf.clear()
    if isinstance(lines, str):
        lines = [lines]
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        run = p.add_run()
        run.text = line
        _apply_format(run, fmt)


def find_title_placeholder(slide):
    # Prefer real placeholders (the template's title region) over text boxes.
    for shape in slide.shapes:
        if shape.has_text_frame and "PLACEHOLDER" in str(shape.shape_type):
            return shape
    return None


def find_largest_textbox(slide, exclude=()):
    # By AREA, not by char count. The Stormbreakers slide 6 has a small
    # "footnote" textbox whose text happens to be longer in characters than
    # the big headline; we want the headline.
    excluded_ids = {id(s) for s in exclude if s is not None}
    largest, largest_area = None, -1
    for shape in slide.shapes:
        if id(shape) in excluded_ids:
            continue
        if not shape.has_text_frame:
            continue
        try:
            area = (shape.width or 0) * (shape.height or 0)
        except Exception:
            area = 0
        if area > largest_area:
            largest, largest_area = shape, area
    return largest


# ---------- slide-specific application ------------------------------------

def apply_slide(slide, slide_idx, mapping):
    """Apply the content map for a slide. For slide 1 the mapping is keyed by
    the literal old text; for all others it uses 'title' + 'body' keys.

    Implementation note: we collect shape references ONCE into a list, then
    compare using `is`. python-pptx's `slide.shapes` iterator creates fresh
    Python wrapper objects on every access, so `id(s1) == id(s2)` is not a
    reliable equality check between two separate iterations -- but a single
    captured reference compared with `is` is.
    """
    if slide_idx == 1:
        for shape in slide.shapes:
            if not shape.has_text_frame:
                continue
            for old_text, new_text in mapping.items():
                if old_text in (shape.text_frame.text or ""):
                    replace_textframe(shape.text_frame, new_text)
                    break
        return

    # Capture all text-frame shapes once. Subsequent comparisons use `is`.
    text_shapes = [sh for sh in slide.shapes if sh.has_text_frame]

    # Identify title: prefer a real PLACEHOLDER; fall back to lowest-y text box.
    title_shape = next(
        (sh for sh in text_shapes if "PLACEHOLDER" in str(sh.shape_type)),
        None,
    )
    if title_shape is None and text_shapes:
        title_shape = min(
            text_shapes,
            key=lambda sh: (sh.top or 0) if (sh.text_frame.text or "").strip() else 10**9,
        )

    # Identify body: largest-area non-title text frame.
    non_title = [sh for sh in text_shapes if sh is not title_shape]
    body_shape = None
    if non_title:
        body_shape = max(
            non_title,
            key=lambda sh: (sh.width or 0) * (sh.height or 0),
        )

    # Apply title + body.
    if title_shape is not None and mapping.get("title"):
        replace_textframe(title_shape.text_frame, mapping["title"])
    if body_shape is not None and mapping.get("body"):
        replace_textframe(body_shape.text_frame, mapping["body"])

    # Clear leftover non-template text in any other text boxes (e.g. the
    # asterisk footnote on slide 6). Skip placeholders (template-managed).
    for sh in non_title:
        if sh is body_shape:
            continue
        if "PLACEHOLDER" in str(sh.shape_type):
            continue
        if not (sh.text_frame.text or "").strip():
            continue
        replace_textframe(sh.text_frame, "")


# ---------- main ----------------------------------------------------------

def build() -> Path:
    if not TEMPLATE.exists():
        raise FileNotFoundError(f"Template not found: {TEMPLATE}")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(TEMPLATE, OUTPUT)
    print(f"copied template -> {OUTPUT}")

    prs = Presentation(str(OUTPUT))
    for slide_idx, mapping in CONTENT.items():
        if slide_idx > len(prs.slides):
            continue
        slide = prs.slides[slide_idx - 1]
        apply_slide(slide, slide_idx, mapping)
        print(f"  slide {slide_idx:2d}: content applied")

    prs.save(str(OUTPUT))
    return OUTPUT


if __name__ == "__main__":
    out = build()
    size_kb = out.stat().st_size / 1024
    print(f"\nOK: {out}  ({size_kb:.1f} KB)")
    sys.exit(0)
