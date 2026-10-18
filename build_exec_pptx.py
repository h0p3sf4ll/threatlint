#!/usr/bin/env python3
"""Generate threatlint executive PPTX — 5-slide, 10-minute deck."""

import os

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt

NAVY   = RGBColor(0x0D, 0x1B, 0x2A)
AMBER  = RGBColor(0xD9, 0x77, 0x06)
WHITE  = RGBColor(0xFF, 0xFF, 0xFF)
OFFWHT = RGBColor(0xF4, 0xF6, 0xF9)
GREY   = RGBColor(0x6B, 0x7A, 0x8D)
INK    = RGBColor(0x1A, 0x23, 0x30)
RED    = RGBColor(0xC0, 0x39, 0x2B)
MUTED  = RGBColor(0x8A, 0x95, 0xA3)
DARK   = RGBColor(0x16, 0x2A, 0x3D)

W = Inches(13.33)
H = Inches(7.5)

prs = Presentation()
prs.slide_width  = W
prs.slide_height = H
blank = prs.slide_layouts[6]


def rect(slide, x, y, w, h, rgb):
    s = slide.shapes.add_shape(1, x, y, w, h)
    s.line.fill.background()
    s.fill.solid()
    s.fill.fore_color.rgb = rgb
    return s


def txt(slide, text, x, y, w, h, size=16, bold=False, color=WHITE,
        align=PP_ALIGN.LEFT):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.alignment = align
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.color.rgb = color
    return tb


def header(slide, title):
    rect(slide, 0, 0, W, H, OFFWHT)
    rect(slide, 0, 0, W, Inches(1.1), NAVY)
    rect(slide, 0, Inches(1.1), Inches(0.06), H - Inches(1.1), AMBER)
    txt(slide, title,
        Inches(0.25), Inches(0.16), Inches(12.6), Inches(0.78),
        size=28, bold=True, color=WHITE)


# ── Slide 1: Title ─────────────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
rect(s, 0, 0, W, H, NAVY)
rect(s, 0, H - Inches(0.08), W, Inches(0.08), AMBER)
rect(s, 0, Inches(3.1), W, Inches(0.04), AMBER)

txt(s, "threatlint",
    Inches(0.8), Inches(0.75), Inches(11.73), Inches(2.0),
    size=84, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
txt(s, "AI-powered application security — built into the tools your teams already use",
    Inches(0.8), Inches(3.3), Inches(11.73), Inches(0.7),
    size=22, color=AMBER, align=PP_ALIGN.CENTER)
txt(s, "Claude · OpenAI · GitHub Models · Local LLMs  ·  GitHub · Azure · Teams · CI/CD  ·  Zero new infrastructure",
    Inches(0.8), Inches(4.15), Inches(11.73), Inches(0.5),
    size=15, color=MUTED, align=PP_ALIGN.CENTER)


# ── Slide 2: The Problem ────────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
header(s, "Security Can't Keep Pace With Development")

problems = [
    ("Bottleneck",
     "Security reviews take days. Developers ship in hours. Critical gaps reach production undetected."),
    ("Noise, Not Signal",
     "Traditional scanners produce thousands of alerts. Teams learn to ignore them — and miss the real risks."),
    ("Point-in-Time Coverage",
     "Threat models go stale the moment code changes. Compliance evidence is assembled manually, each quarter."),
]

for i, (title, body) in enumerate(problems):
    y = Inches(1.35 + 1.9 * i)
    rect(s, Inches(0.28), y, Inches(12.75), Inches(1.68), WHITE)
    rect(s, Inches(0.28), y, Inches(0.45), Inches(1.68), RED)
    txt(s, title, Inches(0.88), y + Inches(0.18),
        Inches(11.8), Inches(0.44),
        size=17, bold=True, color=INK)
    txt(s, body, Inches(0.88), y + Inches(0.65),
        Inches(11.8), Inches(0.85),
        size=14, color=GREY)


# ── Slide 3: The Solution ───────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
header(s, "Meet threatlint — 14 AI Security Agents, Zero Infrastructure")

# Left: what it does
rect(s, Inches(0.28), Inches(1.25), Inches(5.95), Inches(5.85), WHITE)
txt(s, "What it does", Inches(0.5), Inches(1.42),
    Inches(5.5), Inches(0.42), size=15, bold=True, color=NAVY)

capabilities = [
    "Threat-models any codebase on demand",
    "Reviews every PR before it merges",
    "Scans for secrets, CVEs, and misconfigs",
    "Generates compliance evidence automatically",
    "Tracks what's fixed — and what's regressed",
    "Read-only: never modifies your code",
]
for i, cap in enumerate(capabilities):
    txt(s, "✓  " + cap,
        Inches(0.5), Inches(1.98 + 0.74 * i),
        Inches(5.7), Inches(0.62),
        size=14, color=INK)

# Right: where it works
rect(s, Inches(6.55), Inches(1.25), Inches(6.5), Inches(5.85), WHITE)
txt(s, "Works where your teams already are",
    Inches(6.75), Inches(1.42), Inches(6.1), Inches(0.42),
    size=15, bold=True, color=NAVY)

platforms = [
    ("Claude Code",      NAVY,                      "Slash commands in any repository"),
    ("GitHub Copilot",   RGBColor(0x1F,0x88,0x3D),  "@ picker in VS Code / Copilot Chat"),
    ("Microsoft Teams",  RGBColor(0x62,0x64,0xA7),  "Chat commands — no developer tooling needed"),
    ("GitHub Actions",   RGBColor(0x23,0x8B,0x9D),  "13 auto-triggered workflows + PR gating"),
    ("Azure Pipelines",  RGBColor(0x00,0x78,0xD4),  "12 reusable YAML templates"),
    ("OpenAI / Local",   RGBColor(0x6D,0x28,0xD9),  "GPT-5.6 family or fully on-device"),
]
for i, (plat, dot_color, desc) in enumerate(platforms):
    y = Inches(1.98 + 0.74 * i)
    rect(s, Inches(6.75), y + Inches(0.12), Inches(0.25), Inches(0.25), dot_color)
    txt(s, plat, Inches(7.12), y, Inches(2.65), Inches(0.38),
        size=13, bold=True, color=INK)
    txt(s, desc, Inches(7.12), y + Inches(0.36), Inches(5.7), Inches(0.32),
        size=12, color=GREY)


# ── Slide 4: Business Value ─────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
rect(s, 0, 0, W, H, NAVY)
rect(s, 0, H - Inches(0.08), W, Inches(0.08), AMBER)

txt(s, "The Business Case",
    Inches(0.8), Inches(0.28), Inches(11.73), Inches(0.7),
    size=34, bold=True, color=WHITE, align=PP_ALIGN.CENTER)

metrics = [
    ("Minutes",    "not days",       "Security review turnaround — from PR open to findings posted in the thread"),
    ("Every PR",   "not quarterly",  "Continuous coverage — every change reviewed before it reaches main"),
    ("14 domains", "one tool",       "Threat modeling to compliance mapping — no stitching separate tools together"),
    ("No new infra", "flexible cost model",  "Deploy to GitHub, Azure, Teams, VS Code — no new platform. Pay per token with Claude or OpenAI, or run fully on-device with local models at zero token cost."),
]

for i, (big, small, desc) in enumerate(metrics):
    row, col = divmod(i, 2)
    x = Inches(0.45 + 6.3 * col)
    y = Inches(1.25 + 2.7 * row)
    rect(s, x, y, Inches(6.0), Inches(2.42), DARK)
    rect(s, x, y, Inches(6.0), Inches(0.07), AMBER)
    txt(s, big,
        x + Inches(0.22), y + Inches(0.2), Inches(5.6), Inches(0.85),
        size=42, bold=True, color=AMBER)
    txt(s, small,
        x + Inches(0.22), y + Inches(1.0), Inches(5.6), Inches(0.38),
        size=17, color=WHITE)
    txt(s, desc,
        x + Inches(0.22), y + Inches(1.44), Inches(5.6), Inches(0.82),
        size=12, color=MUTED)


# ── Slide 5: Next Step ──────────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
header(s, "Start in Under 5 Minutes")

steps = [
    ("1",
     "Copy the Agents",
     "Claude Code:  ~/.claude/agents/\nCopilot Chat:  .github/agents/\nOpenAI / Local:  appsec_api.py\n                  --provider openai|lmstudio\n\nCloud: set ANTHROPIC_API_KEY,\n       OPENAI_API_KEY, or GITHUB_TOKEN.\nOn-device: point to a local LLM —\n       no API key, no token cost."),
    ("2",
     "Run Your First Review",
     "Open Claude Code and type /threat-model.\nRuns locally — no server, no deployment.\nUse Anthropic, OpenAI, GitHub Models,\nor a local model (LM Studio / Ollama)\nfor zero token cost on-device."),
    ("3",
     "Automate It",
     "Add your API key (Anthropic, OpenAI, or GitHub Models) to repo secrets — or point to a local model for zero token cost.\nEvery PR is reviewed and gated automatically."),
]

for i, (num, title, body) in enumerate(steps):
    x = Inches(0.35 + 4.28 * i)
    rect(s, x, Inches(1.3), Inches(4.1), Inches(5.65), WHITE)
    rect(s, x, Inches(1.3), Inches(4.1), Inches(0.52), NAVY)
    rect(s, x, Inches(1.3), Inches(0.52), Inches(0.52), AMBER)
    txt(s, num,
        x + Inches(0.08), Inches(1.35), Inches(0.36), Inches(0.42),
        size=20, bold=True, color=NAVY, align=PP_ALIGN.CENTER)
    txt(s, title,
        x + Inches(0.62), Inches(1.37), Inches(3.34), Inches(0.38),
        size=16, bold=True, color=WHITE)
    txt(s, body,
        x + Inches(0.18), Inches(2.05), Inches(3.76), Inches(4.7),
        size=14, color=INK)

txt(s, "Open source  ·  github.com/h0p3sf4ll/threatlint  ·  Read-only  ·  Zero infrastructure",
    Inches(0.8), Inches(7.05), Inches(11.73), Inches(0.35),
    size=12, color=GREY, align=PP_ALIGN.CENTER)


# ── Slide 6: All 14 Agents ─────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
header(s, "14 Specialist Agents — One for Every Security Domain")

CAT_AMBER  = RGBColor(0xD9, 0x77, 0x06)
CAT_TEAL   = RGBColor(0x17, 0x7A, 0x8A)
CAT_BLUE   = RGBColor(0x00, 0x6A, 0xBD)
CAT_PURPLE = RGBColor(0x5E, 0x22, 0xBF)

categories = [
    ("Discover & Model", CAT_AMBER, [
        ("Threat Modeler",    "STRIDE · ATT&CK · DREAD across the full codebase"),
        ("Attack Tree",       "AND/OR trees with bypass analysis and leaf-node ranking"),
        ("Red Team",          "5 adversarial kill chains with IoCs and purple-team tests"),
    ]),
    ("Review & Detect", CAT_TEAL, [
        ("Code Reviewer",     "Security review of PRs, diffs, and risky config changes"),
        ("Secrets Scanner",   "API keys, tokens, and high-entropy strings in code and history"),
        ("API Security",      "OWASP API Top 10 — REST, GraphQL, gRPC, WebSocket"),
        ("Auth Reviewer",     "OAuth, JWT, RBAC, session management, MFA, SSO"),
    ]),
    ("Infrastructure", CAT_BLUE, [
        ("IaC Reviewer",      "Terraform, K8s, Dockerfile, CloudFormation, Helm"),
        ("CI/CD Auditor",     "GitHub Actions, Jenkins, GitLab CI, Azure Pipelines"),
        ("Dependency Auditor","CVEs, dependency confusion, supply chain, lockfile integrity"),
    ]),
    ("Measure & Report", CAT_PURPLE, [
        ("Compliance",        "ASVS · PCI-DSS · HIPAA · SOC 2 · ISO 27001 · NIST · CIS"),
        ("FP Reviewer",       "Triage scanner findings · generate Semgrep tuning rules"),
        ("Threat Delta",      "Compares prior report to current state: RESOLVED / REGRESSED / NEW"),
        ("Verify Fix",        "Confirms a specific finding is REMEDIATED or STILL PRESENT"),
    ]),
]

COL_W   = Inches(3.08)
COL_GAP = Inches(0.14)
START_X = Inches(0.33)
TOP_Y   = Inches(1.2)
CAT_H   = Inches(0.46)
ROW_H   = Inches(1.2)

for ci, (cat_title, cat_color, agents_list) in enumerate(categories):
    x = START_X + ci * (COL_W + COL_GAP)
    # category header
    rect(s, x, TOP_Y, COL_W, CAT_H, cat_color)
    txt(s, cat_title,
        x + Inches(0.12), TOP_Y + Inches(0.07), COL_W - Inches(0.15), Inches(0.34),
        size=13, bold=True, color=WHITE)
    # agent rows
    for ai, (agent_name, agent_desc) in enumerate(agents_list):
        ay = TOP_Y + CAT_H + ai * ROW_H
        rect(s, x, ay, COL_W, ROW_H, WHITE)
        rect(s, x, ay, Inches(0.04), ROW_H, cat_color)
        # separator line between rows (except last)
        if ai < len(agents_list) - 1:
            rect(s, x, ay + ROW_H - Inches(0.02), COL_W, Inches(0.02),
                 RGBColor(0xE8, 0xEB, 0xEF))
        txt(s, agent_name,
            x + Inches(0.14), ay + Inches(0.1), COL_W - Inches(0.18), Inches(0.38),
            size=13, bold=True, color=INK)
        txt(s, agent_desc,
            x + Inches(0.14), ay + Inches(0.48), COL_W - Inches(0.18), Inches(0.62),
            size=11, color=GREY)


# ── Save ───────────────────────────────────────────────────────────────────
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "threatlint-exec-10min.pptx")
prs.save(OUT)
print(f"Saved: {OUT}  ({len(prs.slides)} slides)")
