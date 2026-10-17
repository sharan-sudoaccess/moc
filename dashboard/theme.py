"""Visual system for the dashboard: CSS, colour tokens and small HTML helpers.

Every piece of user-supplied text is passed through html.escape before it is
placed into markup.
"""

from __future__ import annotations

from html import escape

SEVERITY_COLORS = {
    "critical": "#F0506E",
    "high": "#F59E42",
    "medium": "#E7C547",
    "low": "#5B9CF6",
    None: "#8592A6",
}
LEVEL_COLORS = {
    "CRITICAL": "#F0506E",
    "HIGH": "#F59E42",
    "MEDIUM": "#E7C547",
    "LOW": "#5B9CF6",
    "NONE": "#3FB68B",
}
ACTION_COLORS = {"ALLOW": "#3FB68B", "FLAG": "#E7C547", "BLOCK": "#F0506E"}
ACCENT = "#38BDF8"
MUTED = "#8592A6"
PANEL = "#111722"
GRID = "#232D3D"

CSS = """
<style>
:root {
  --bg: #0A0E14; --panel: #111722; --panel-2: #161E2B; --border: #232D3D;
  --text: #D7DEE8; --muted: #8592A6; --accent: #38BDF8;
  --mono: "JetBrains Mono", "SFMono-Regular", "Cascadia Code", Menlo, Consolas, monospace;
}
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1400px; }
h1, h2, h3 { letter-spacing: -0.01em; }
[data-testid="stSidebar"] { border-right: 1px solid var(--border); }
[data-testid="stSidebar"] .stRadio label p { font-size: 0.93rem; }
code, pre { font-family: var(--mono) !important; }

.page-title { display:flex; align-items:baseline; gap:.75rem; margin-bottom:.15rem; }
.page-title h1 { font-size:1.55rem; font-weight:650; margin:0; padding:0; }
.page-title .crumb { color:var(--muted); font-family:var(--mono); font-size:.78rem; text-transform:uppercase; letter-spacing:.08em; }
.page-sub { color:var(--muted); font-size:.92rem; margin-bottom:1.1rem; }

.kpi { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:.85rem 1rem .8rem; height:100%; }
.kpi .label { color:var(--muted); font-size:.72rem; text-transform:uppercase; letter-spacing:.08em; font-weight:600; }
.kpi .value { font-size:1.65rem; font-weight:650; font-family:var(--mono); margin-top:.15rem; line-height:1.2; }
.kpi .sub { color:var(--muted); font-size:.78rem; margin-top:.2rem; }
.kpi.tone { border-left-width:3px; }

.badge { display:inline-block; padding:.08rem .5rem; border-radius:4px; font-size:.72rem; font-weight:700;
  font-family:var(--mono); letter-spacing:.04em; border:1px solid; white-space:nowrap; }

.verdict { border:1px solid var(--border); border-left:4px solid; border-radius:8px; background:var(--panel);
  padding:1rem 1.2rem; display:flex; gap:1.4rem; align-items:center; flex-wrap:wrap; }
.verdict .action { font-family:var(--mono); font-size:1.9rem; font-weight:800; letter-spacing:.06em; }
.verdict .summary { flex:1; min-width:260px; color:var(--text); font-size:.95rem; }
.verdict .meta { color:var(--muted); font-family:var(--mono); font-size:.75rem; margin-top:.3rem; }

.scorebar { height:8px; background:var(--panel-2); border-radius:4px; overflow:hidden; border:1px solid var(--border); }
.scorebar > div { height:100%; }

.evidence { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:.9rem 1rem;
  font-family:var(--mono); font-size:.88rem; line-height:1.7; white-space:pre-wrap; word-break:break-word; }
.evidence mark { color:#0A0E14; border-radius:3px; padding:.05rem .15rem; font-weight:600; }

.tape { display:flex; flex-wrap:wrap; gap:.35rem; padding:.2rem 0 .4rem; }
.tok { border:1px solid var(--border); background:var(--panel); border-radius:6px; padding:.3rem .5rem;
  min-width:64px; text-align:center; font-family:var(--mono); }
.tok .w { font-size:.85rem; color:var(--text); }
.tok .s { font-size:.66rem; color:var(--muted); margin-top:.1rem; }
.tok .q { font-size:.72rem; margin-top:.15rem; color:var(--accent); }
.tok.skip { opacity:.55; border-style:dashed; }
.tok.reset .q { color:var(--muted); }
.tok.accept { border-color:#F0506E; box-shadow:0 0 0 1px #F0506E inset; }
.tok.accept .q { color:#F0506E; font-weight:700; }

.note { color:var(--muted); font-size:.82rem; }
.panel-title { font-size:.78rem; text-transform:uppercase; letter-spacing:.08em; color:var(--muted);
  font-weight:600; margin:.4rem 0 .5rem; }
.legend span { margin-right:1rem; font-size:.78rem; color:var(--muted); font-family:var(--mono); }
.status-dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:.4rem; }
.sidebar-brand { font-family:var(--mono); font-weight:700; font-size:1.0rem; letter-spacing:.04em; }
.sidebar-brand span { color:var(--accent); }
.sidebar-tag { color:var(--muted); font-size:.72rem; text-transform:uppercase; letter-spacing:.1em; }
</style>
"""


def page_header(title: str, crumb: str, subtitle: str) -> str:
    return (
        f'<div class="page-title"><span class="crumb">{escape(crumb)}</span><h1>{escape(title)}</h1></div>'
        f'<div class="page-sub">{escape(subtitle)}</div>'
    )


def badge(text: str, color: str) -> str:
    return (
        f'<span class="badge" style="color:{color};border-color:{color}55;background:{color}14">'
        f"{escape(str(text))}</span>"
    )


def severity_badge(severity: str | None) -> str:
    return badge((severity or "none").upper(), SEVERITY_COLORS.get(severity, MUTED))


def action_badge(action: str) -> str:
    return badge(action, ACTION_COLORS.get(action, MUTED))


def kpi(label: str, value: str, sub: str | None = None, color: str | None = None) -> str:
    style = f' style="border-left-color:{color}"' if color else ""
    cls = "kpi tone" if color else "kpi"
    value_style = f' style="color:{color}"' if color else ""
    sub_html = f'<div class="sub">{escape(sub)}</div>' if sub else ""
    return (
        f'<div class="{cls}"{style}><div class="label">{escape(label)}</div>'
        f'<div class="value"{value_style}>{escape(str(value))}</div>{sub_html}</div>'
    )


def score_bar(score: float, level: str) -> str:
    color = LEVEL_COLORS.get(level, MUTED)
    width = max(0.0, min(100.0, float(score)))
    return f'<div class="scorebar"><div style="width:{width}%;background:{color}"></div></div>'


def verdict_banner(result: dict) -> str:
    action = result["action"]
    color = ACTION_COLORS.get(action, MUTED)
    level = result["risk_level"]
    return (
        f'<div class="verdict" style="border-left-color:{color}">'
        f'<div class="action" style="color:{color}">{escape(action)}</div>'
        f'<div class="summary">{escape(result["summary"])}'
        f'<div class="meta">request {escape(result["request_id"])} · policy {escape(result["policy"])} · '
        f'ruleset {escape(result["ruleset_version"])} ({escape(result["ruleset_fingerprint"])}) · '
        f'detector v{escape(result["detector_version"])}</div></div>'
        f'<div style="min-width:180px"><div class="kpi" style="border:none;padding:0;background:transparent">'
        f'<div class="label">Risk score · {escape(level)}</div>'
        f'<div class="value" style="color:{LEVEL_COLORS.get(level, MUTED)}">{result["risk_score"]:.1f}'
        f'<span style="font-size:.9rem;color:var(--muted)"> / 100</span></div></div>'
        f"{score_bar(result['risk_score'], level)}</div></div>"
    )


_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def highlight_evidence(text: str, matches: list[dict]) -> str:
    """Original text with every matched span highlighted (overlaps merged)."""
    if not matches:
        return f'<div class="evidence">{escape(text)}</div>'
    spans = sorted((m["start_char"], m["end_char"], m["severity"], m["rule_id"]) for m in matches)
    merged: list[list] = []
    for start, end, sev, rid in spans:
        if merged and start <= merged[-1][1]:
            last = merged[-1]
            last[1] = max(last[1], end)
            if _SEV_RANK[sev] > _SEV_RANK[last[2]]:
                last[2] = sev
            last[3].append(rid)
        else:
            merged.append([start, end, sev, [rid]])
    out, cursor = [], 0
    for start, end, sev, rids in merged:
        out.append(escape(text[cursor:start]))
        title = ", ".join(sorted(set(rids)))
        out.append(
            f'<mark style="background:{SEVERITY_COLORS[sev]}" title="{escape(title)}">'
            f"{escape(text[start:end])}</mark>"
        )
        cursor = end
    out.append(escape(text[cursor:]))
    return f'<div class="evidence">{"".join(out)}</div>'


def token_tape(trace: list[dict]) -> str:
    chips = []
    for step in trace:
        kind = step["transition"]
        classes = ["tok", kind]
        if step["outputs"]:
            classes.append("accept")
        symbol = step["symbol"] if step["symbol"].startswith("⟨") else "∈ V"
        out = f' ⇒ {escape(", ".join(step["outputs"]))}' if step["outputs"] else ""
        chips.append(
            f'<div class="{" ".join(classes)}" title="step {step["step"]}: δ(q{step["from_state"]}, '
            f'{escape(step["symbol"])}) = q{step["to_state"]} [{kind}]">'
            f'<div class="w">{escape(step["token"])}</div>'
            f'<div class="s">{escape(symbol)} · {escape(kind)}</div>'
            f'<div class="q">q{step["from_state"]}→q{step["to_state"]}{out}</div></div>'
        )
    return f'<div class="tape">{"".join(chips)}</div>'


def status_dot(ok: bool) -> str:
    color = "#3FB68B" if ok else "#F0506E"
    return f'<span class="status-dot" style="background:{color}"></span>'
