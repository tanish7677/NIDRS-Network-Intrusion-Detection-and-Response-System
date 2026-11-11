"""
NIDRS dashboard - UI toolkit
============================
One place for everything visual, so app.py only has to say WHAT to show:

    inject_theme()                     global CSS (colours, cards, sidebar...)
    page_header(title, subtitle, chips)
    status_banner(level, ...)          big network-status strip
    kpi_row([...])                     row of KPI cards
    section(title, subtitle)           section heading
    table(df, ...)                     st.dataframe with severity colouring
    plotly_chart(fig, ...)             st.plotly_chart with the NIDRS look
    sidebar_brand() / sidebar_status() / sidebar_user()

Design: calm "security operations" console - dark slate surfaces, a single
blue accent, and four severity colours (Critical / High / Medium / Low)
used consistently in cards, badges, tables and charts.
"""

from datetime import datetime
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st


# ---------------------------------------------------------------
# DESIGN TOKENS
# ---------------------------------------------------------------

SEVERITY_COLORS = {
    "Critical": "#EF4444",
    "High": "#F97316",
    "Medium": "#EAB308",
    "Low": "#22C55E",
}

THREAT_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F97316",
    "MEDIUM": "#EAB308",
    "LOW": "#22C55E",
}

CHART_COLORWAY = [
    "#3B82F6", "#8B5CF6", "#14B8A6", "#F59E0B", "#EC4899", "#64748B",
]

NAV_ICONS = {
    "Dashboard": "🏠",
    "Dataset Attacks": "🧪",
    "Live Anomalies": "🌐",
    "Response Center": "🛠️",
    "Response History": "🕘",
    "📈 Analytics": "📈",
    "System Architecture": "🏗️",
    "Logs": "📜",
    "Settings": "⚙️",
}


def nav_label(page):
    """Sidebar label: icon + plain page name (the page value stays unchanged)."""

    name = page.replace("📈 ", "")

    return f"{NAV_ICONS.get(page, '•')}  {name}"


# ---------------------------------------------------------------
# GLOBAL CSS
# ---------------------------------------------------------------

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg: #0B1220;
    --surface: #111A2C;
    --surface-2: #16213A;
    --border: #22304D;
    --border-strong: #33456E;
    --text: #E6EAF2;
    --muted: #8C99B4;
    --accent: #3B82F6;
    --accent-soft: rgba(59, 130, 246, 0.14);
    --critical: #EF4444;
    --high: #F97316;
    --medium: #EAB308;
    --low: #22C55E;
    --radius: 12px;
}

html, body, .stApp {
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif;
}
.stApp {
    background:
        radial-gradient(1100px 480px at 88% -8%, rgba(59,130,246,0.09), transparent 60%),
        var(--bg);
}

header[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer { visibility: hidden; }

.main .block-container {
    padding-top: 1.6rem;
    padding-bottom: 3rem;
    max-width: 1500px;
}

/* ---------- typography ---------- */
h1, h2, h3, h4 {
    font-family: 'Inter', sans-serif !important;
    color: var(--text) !important;
    letter-spacing: -0.01em;
    font-weight: 700 !important;
}
h1 { font-size: 1.75rem !important; margin-bottom: 0.6rem !important; }
h2 { font-size: 1.25rem !important; margin-top: 1.4rem !important; }
h3 { font-size: 1.05rem !important; margin-top: 1.2rem !important; }
p, li, label, .stMarkdown, .stCaption, [data-testid="stCaptionContainer"] {
    color: var(--muted);
}
.stMarkdown strong, .stMarkdown b { color: var(--text); }
a { color: var(--accent) !important; }

code, .stCode, pre,
div[data-testid="stMetricValue"],
div[data-testid="stDataFrame"] * {
    font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace !important;
}
div[data-testid="stDataFrame"] * { font-size: 0.82rem; }

hr { border: 0; border-top: 1px solid var(--border) !important; margin: 1.4rem 0; }

/* ---------- page header ---------- */
.nx-header {
    display: flex; align-items: center; justify-content: space-between;
    gap: 16px; flex-wrap: wrap;
    padding: 4px 0 18px 0; margin-bottom: 18px;
    border-bottom: 1px solid var(--border);
}
.nx-header-left { display: flex; align-items: center; gap: 14px; min-width: 0; }
.nx-header-icon {
    width: 46px; height: 46px; border-radius: 12px; flex: none;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.4rem;
    background: var(--accent-soft); border: 1px solid rgba(59,130,246,0.35);
}
.nx-title { font-size: 1.55rem; font-weight: 700; color: var(--text); line-height: 1.2; }
.nx-subtitle { font-size: 0.92rem; color: var(--muted); margin-top: 3px; }
.nx-chips { display: flex; gap: 8px; flex-wrap: wrap; }

/* ---------- chips & badges ---------- */
.nx-chip {
    display: inline-flex; align-items: center; gap: 7px;
    padding: 5px 12px; border-radius: 999px;
    font-size: 0.78rem; font-weight: 600; white-space: nowrap;
    background: var(--surface); border: 1px solid var(--border); color: var(--muted);
}
.nx-chip.ok     { color: #86EFAC; border-color: rgba(34,197,94,0.35);  background: rgba(34,197,94,0.08); }
.nx-chip.warn   { color: #FDE047; border-color: rgba(234,179,8,0.35);  background: rgba(234,179,8,0.08); }
.nx-chip.high   { color: #FDBA74; border-color: rgba(249,115,22,0.38); background: rgba(249,115,22,0.09); }
.nx-chip.danger { color: #FCA5A5; border-color: rgba(239,68,68,0.40);  background: rgba(239,68,68,0.10); }
.nx-chip.info   { color: #93C5FD; border-color: rgba(59,130,246,0.40); background: rgba(59,130,246,0.10); }
.nx-dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; display: inline-block; }
.nx-dot.pulse { animation: nx-pulse 1.8s infinite; }
@keyframes nx-pulse {
    0%   { box-shadow: 0 0 0 0 currentColor; opacity: 1; }
    70%  { box-shadow: 0 0 0 7px rgba(0,0,0,0); opacity: .75; }
    100% { box-shadow: 0 0 0 0 rgba(0,0,0,0); opacity: 1; }
}

.nx-badge {
    display: inline-block; padding: 2px 10px; border-radius: 6px;
    font-size: 0.74rem; font-weight: 700; letter-spacing: .02em;
}
.nx-badge.Critical { background: rgba(239,68,68,0.16);  color: #FCA5A5; }
.nx-badge.High     { background: rgba(249,115,22,0.16); color: #FDBA74; }
.nx-badge.Medium   { background: rgba(234,179,8,0.16);  color: #FDE047; }
.nx-badge.Low      { background: rgba(34,197,94,0.16);  color: #86EFAC; }

/* ---------- status banner ---------- */
.nx-banner {
    display: flex; align-items: center; gap: 16px;
    padding: 16px 20px; margin-bottom: 18px;
    border-radius: var(--radius);
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 5px solid var(--lvl);
    box-shadow: 0 6px 24px rgba(0,0,0,0.25);
}
.nx-banner-dot {
    width: 14px; height: 14px; border-radius: 50%; flex: none;
    background: var(--lvl); color: var(--lvl);
    animation: nx-pulse 1.8s infinite;
}
.nx-banner-title { font-size: 1.02rem; font-weight: 700; color: var(--text); }
.nx-banner-text { font-size: 0.88rem; color: var(--muted); margin-top: 2px; }
.nx-banner-level {
    margin-left: auto; font-size: 0.78rem; font-weight: 700; letter-spacing: .08em;
    padding: 5px 12px; border-radius: 6px; color: var(--lvl);
    border: 1px solid var(--lvl); white-space: nowrap;
}

/* ---------- KPI cards ---------- */
.nx-kpi-grid {
    display: grid; gap: 14px; margin-bottom: 8px;
    grid-template-columns: repeat(auto-fit, minmax(185px, 1fr));
}
.nx-kpi {
    position: relative; overflow: hidden;
    padding: 16px 18px 14px 18px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: 0 4px 18px rgba(0,0,0,0.22);
}
.nx-kpi::before {
    content: ""; position: absolute; left: 0; top: 0; right: 0; height: 3px;
    background: var(--accent-c);
}
.nx-kpi-top { display: flex; justify-content: space-between; align-items: center; }
.nx-kpi-label {
    font-size: 0.72rem; font-weight: 600; letter-spacing: .06em;
    text-transform: uppercase; color: var(--muted);
}
.nx-kpi-icon {
    width: 30px; height: 30px; border-radius: 8px; font-size: 0.95rem;
    display: flex; align-items: center; justify-content: center;
    background: var(--surface-2);
}
.nx-kpi-value {
    font-family: 'JetBrains Mono', monospace; font-variant-numeric: tabular-nums;
    font-size: 2rem; font-weight: 600; color: var(--accent-c);
    margin: 8px 0 2px 0; line-height: 1.1;
}
.nx-kpi-sub { font-size: 0.78rem; color: var(--muted); }

/* ---------- native st.metric (other pages) ---------- */
div[data-testid="stMetric"], div[data-testid="metric-container"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-top: 3px solid var(--accent);
    padding: 14px 18px; border-radius: var(--radius);
    box-shadow: 0 4px 18px rgba(0,0,0,0.22);
}
div[data-testid="stMetricLabel"] {
    color: var(--muted) !important; font-weight: 600 !important;
    text-transform: uppercase; letter-spacing: .05em; font-size: 0.72rem !important;
}
div[data-testid="stMetricValue"] { color: var(--text) !important; font-weight: 600 !important; }

/* ---------- section heading ---------- */
.nx-section { margin: 26px 0 12px 0; }
.nx-section-title { font-size: 1.05rem; font-weight: 700; color: var(--text); }
.nx-section-sub { font-size: 0.85rem; color: var(--muted); margin-top: 2px; }

/* ---------- buttons ---------- */
.stButton > button, .stFormSubmitButton > button, .stDownloadButton > button {
    border-radius: 9px; font-weight: 600; font-size: 0.88rem;
    background: var(--surface-2); color: var(--text);
    border: 1px solid var(--border-strong);
    transition: background .15s ease, border-color .15s ease;
}
.stButton > button:hover, .stFormSubmitButton > button:hover, .stDownloadButton > button:hover {
    border-color: var(--accent); color: #fff; background: var(--accent-soft);
}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
    background: var(--accent) !important; border-color: var(--accent) !important; color: #fff !important;
}
.stButton > button[kind="primary"]:hover, .stFormSubmitButton > button[kind="primary"]:hover {
    background: #2563EB !important; border-color: #2563EB !important;
}
.stButton > button:disabled {
    background: transparent !important; color: #5B6785 !important;
    border-color: var(--border) !important;
}

/* ---------- inputs ---------- */
div[data-baseweb="input"] > div,
div[data-baseweb="textarea"] > div,
div[data-baseweb="select"] > div {
    background: var(--surface-2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 9px !important; color: var(--text) !important;
}
div[data-baseweb="input"] > div:focus-within,
div[data-baseweb="select"] > div:focus-within { border-color: var(--accent) !important; }
input, textarea { color: var(--text) !important; background: transparent !important; }
input::placeholder, textarea::placeholder { color: #5B6785 !important; }
div[data-baseweb="select"] * { color: var(--text) !important; }
div[data-baseweb="popover"] ul[role="listbox"] {
    background: var(--surface-2) !important;
    border: 1px solid var(--border-strong) !important; border-radius: 9px !important;
}
div[data-baseweb="popover"] li { color: var(--text) !important; }
div[data-baseweb="popover"] li:hover,
div[data-baseweb="popover"] li[aria-selected="true"] { background: var(--accent-soft) !important; }

/* ---------- containers ---------- */
div[data-testid="stForm"] {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 14px; padding: 22px;
    box-shadow: 0 10px 34px rgba(0,0,0,0.35);
}
div[data-testid="stExpander"], details {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius);
}
div[data-testid="stExpander"] summary { color: var(--text) !important; font-weight: 600; }
div[data-testid="stDataFrame"] {
    border: 1px solid var(--border); border-radius: var(--radius);
    overflow: hidden; box-shadow: 0 2px 14px rgba(0,0,0,0.25);
}
div[data-testid="stPlotlyChart"] {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 6px 8px;
    box-shadow: 0 2px 14px rgba(0,0,0,0.25);
}
div[data-testid="stAlert"] {
    border-radius: var(--radius); border: 1px solid var(--border);
    background: var(--surface);
}
button[data-baseweb="tab"] { color: var(--muted) !important; }
button[data-baseweb="tab"][aria-selected="true"] { color: var(--accent) !important; }

/* ---------- sidebar ---------- */
section[data-testid="stSidebar"] {
    background: #0A101D; border-right: 1px solid var(--border);
}
section[data-testid="stSidebar"] > div { padding-top: 1rem; }
.nx-brand { display: flex; align-items: center; gap: 12px; padding: 4px 4px 16px 4px; }
.nx-brand-logo {
    width: 40px; height: 40px; border-radius: 11px; flex: none;
    display: flex; align-items: center; justify-content: center; font-size: 1.25rem;
    background: linear-gradient(135deg, #2563EB, #06B6D4);
    box-shadow: 0 6px 18px rgba(37,99,235,0.35);
}
.nx-brand-name { font-size: 1.15rem; font-weight: 800; letter-spacing: .04em; color: var(--text); line-height: 1.1; }
.nx-brand-tag { font-size: 0.7rem; color: var(--muted); margin-top: 2px; }
.nx-side-label {
    font-size: 0.68rem; font-weight: 700; letter-spacing: .1em;
    text-transform: uppercase; color: #5B6785; margin: 14px 4px 6px 4px;
}
section[data-testid="stSidebar"] div[role="radiogroup"] { gap: 2px; }
section[data-testid="stSidebar"] div[role="radiogroup"] > label {
    padding: 9px 12px; border-radius: 9px; width: 100%;
    border: 1px solid transparent; cursor: pointer;
    transition: background .12s ease;
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:first-child { display: none; }
section[data-testid="stSidebar"] div[role="radiogroup"] > label p {
    color: #AEB9D1; font-size: 0.92rem; font-weight: 500; margin: 0;
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover { background: rgba(255,255,255,0.04); }
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
    background: var(--accent-soft); border-color: rgba(59,130,246,0.35);
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) p {
    color: #fff; font-weight: 600;
}
.nx-side-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 11px; padding: 10px 12px; margin-bottom: 8px;
}
.nx-side-row { display: flex; justify-content: space-between; align-items: center; padding: 3px 0; font-size: 0.8rem; }
.nx-side-row span:first-child { color: var(--muted); }
.nx-side-row span:last-child  { color: var(--text); font-weight: 600; }
.nx-user { display: flex; align-items: center; gap: 10px; padding: 4px 2px 10px 2px; }
.nx-avatar {
    width: 32px; height: 32px; border-radius: 50%; flex: none;
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 0.85rem; color: #fff; background: #2563EB;
}
.nx-user-name { font-size: 0.86rem; font-weight: 600; color: var(--text); line-height: 1.1; }
.nx-user-role { font-size: 0.7rem; color: var(--muted); }

/* ---------- login ---------- */
.nx-login { text-align: center; margin: 7vh 0 22px 0; }
.nx-login .nx-brand-logo { margin: 0 auto 14px auto; width: 58px; height: 58px; font-size: 1.8rem; border-radius: 16px; }
.nx-login-title { font-size: 1.7rem; font-weight: 800; color: var(--text); letter-spacing: .02em; }
.nx-login-sub { font-size: 0.92rem; color: var(--muted); margin-top: 4px; }

/* ---------- scrollbars ---------- */
::-webkit-scrollbar { width: 9px; height: 9px; }
::-webkit-scrollbar-thumb { background: #26334F; border-radius: 6px; }
::-webkit-scrollbar-track { background: transparent; }
</style>
"""


def inject_theme():
    st.markdown(_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------
# SMALL HTML HELPERS
# ---------------------------------------------------------------

def _html(markup):
    """Render HTML; newlines/indentation are stripped so Markdown can't
    mistake the markup for a code block."""

    st.markdown(
        "".join(line.strip() for line in markup.splitlines()),
        unsafe_allow_html=True,
    )


def _split_icon(title):
    """'🛡️ Response Center' -> ('🛡️', 'Response Center')."""

    title = str(title).strip()

    if " " in title:

        head, tail = title.split(" ", 1)

        if head and not head[0].isascii():
            return head, tail.strip()

    return "", title


def badge(text, kind=None):
    kind = kind or text
    return f'<span class="nx-badge {escape(str(kind))}">{escape(str(text))}</span>'


def chip(text, kind="", pulse=False):
    dot = f'<span class="nx-dot{" pulse" if pulse else ""}"></span>'
    return f'<span class="nx-chip {kind}">{dot}{escape(str(text))}</span>'


# ---------------------------------------------------------------
# COMPONENTS
# ---------------------------------------------------------------

def page_header(title, subtitle="", chips=None, icon=None):
    """
    chips: list of (text, kind) or (text, kind, pulse)
           kind: ok | warn | high | danger | info | "" (neutral)
    """

    found_icon, clean_title = _split_icon(title)

    icon = icon or found_icon or "🛡️"

    chips_html = ""

    for item in (chips or []):

        text, kind = item[0], item[1]
        pulse = item[2] if len(item) > 2 else False

        chips_html += chip(text, kind, pulse)

    sub = f'<div class="nx-subtitle">{escape(str(subtitle))}</div>' if subtitle else ""

    _html(f"""
    <div class="nx-header">
      <div class="nx-header-left">
        <div class="nx-header-icon">{escape(icon)}</div>
        <div><div class="nx-title">{escape(clean_title)}</div>{sub}</div>
      </div>
      <div class="nx-chips">{chips_html}</div>
    </div>
    """)


def section(title, subtitle=""):
    found_icon, clean = _split_icon(title)

    label = f"{found_icon} {clean}".strip()

    sub = f'<div class="nx-section-sub">{escape(subtitle)}</div>' if subtitle else ""

    _html(f"""
    <div class="nx-section">
      <div class="nx-section-title">{escape(label)}</div>{sub}
    </div>
    """)


def status_banner(level, recent_count=0, window_minutes=5):
    """Large network-status strip driven by the severity-aware threat level."""

    level = str(level).upper()

    content = {
        "CRITICAL": (
            "Critical network threat detected",
            f"{recent_count} critical anomaly(ies) in the last {window_minutes} "
            "minutes. Immediate investigation is recommended.",
        ),
        "HIGH": (
            "High-risk network activity",
            f"High-severity anomalies seen in the last {window_minutes} minutes.",
        ),
        "MEDIUM": (
            "Network anomaly detected",
            f"Medium-severity anomalies seen in the last {window_minutes} minutes.",
        ),
        "LOW": (
            "Network operating normally",
            f"No anomalies detected in the last {window_minutes} minutes.",
        ),
    }

    title, text = content.get(level, content["LOW"])

    color = THREAT_COLORS.get(level, THREAT_COLORS["LOW"])

    _html(f"""
    <div class="nx-banner" style="--lvl:{color}">
      <div class="nx-banner-dot"></div>
      <div>
        <div class="nx-banner-title">{escape(title)}</div>
        <div class="nx-banner-text">{escape(text)}</div>
      </div>
      <div class="nx-banner-level">THREAT LEVEL: {escape(level)}</div>
    </div>
    """)


def kpi_row(items):
    """items: list of dicts - label, value, sub, color, icon."""

    cards = ""

    for item in items:

        cards += (
            f'<div class="nx-kpi" style="--accent-c:{item.get("color", "#3B82F6")}">'
            f'<div class="nx-kpi-top"><span class="nx-kpi-label">{escape(str(item["label"]))}</span>'
            f'<span class="nx-kpi-icon">{escape(str(item.get("icon", "")))}</span></div>'
            f'<div class="nx-kpi-value">{escape(str(item["value"]))}</div>'
            f'<div class="nx-kpi-sub">{escape(str(item.get("sub", "")))}</div>'
            "</div>"
        )

    st.markdown(f'<div class="nx-kpi-grid">{cards}</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------
# TABLES & CHARTS
# ---------------------------------------------------------------

_SEV_CELL = {
    "Critical": "background-color:#4A1D26;color:#FCA5A5;font-weight:700",
    "High": "background-color:#47260F;color:#FDBA74;font-weight:700",
    "Medium": "background-color:#453A0E;color:#FDE047;font-weight:700",
    "Low": "background-color:#12382A;color:#86EFAC;font-weight:700",
}


def _sev_style(value):
    return _SEV_CELL.get(value, "")


def _status_style(value):
    return "color:#93C5FD;font-weight:600" if value == "New" else ""


def table(data, **kwargs):
    """st.dataframe + colour-coded severity/status columns (falls back to
    a plain dataframe if styling is not possible)."""

    kwargs.setdefault("use_container_width", True)
    kwargs.setdefault("hide_index", True)

    try:
        if (
            isinstance(data, pd.DataFrame)
            and len(data) > 0
            and data.shape[0] * data.shape[1] <= 150_000
            and data.columns.is_unique
        ):

            styler = data.style

            # pandas >= 2.1 renamed Styler.applymap -> Styler.map
            apply_map = getattr(styler, "map", None) or styler.applymap

            if "severity" in data.columns:
                apply_map(_sev_style, subset=["severity"])

            if "status" in data.columns:
                apply_map(_status_style, subset=["status"])

            return st.dataframe(styler, **kwargs)

    except Exception:
        pass

    return st.dataframe(data, **kwargs)


def style_fig(fig):
    """Give any plotly figure the NIDRS look (transparent, slate grid)."""

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        colorway=CHART_COLORWAY,
        font=dict(
            family="Inter, system-ui, sans-serif",
            color="#C9D2E3",
            size=12,
        ),
        title=dict(font=dict(size=15, color="#E6EAF2"), x=0.01, xanchor="left"),
        margin=dict(l=14, r=14, t=52, b=14),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(size=11),
            orientation="h",
            yanchor="bottom",
            y=-0.25,
            x=0,
        ),
        hoverlabel=dict(
            bgcolor="#16213A",
            bordercolor="#33456E",
            font=dict(family="Inter", color="#E6EAF2"),
        ),
    )

    fig.update_xaxes(
        gridcolor="#1B2742", zerolinecolor="#1B2742",
        linecolor="#26334F", tickfont=dict(color="#8C99B4"),
    )
    fig.update_yaxes(
        gridcolor="#1B2742", zerolinecolor="#1B2742",
        linecolor="#26334F", tickfont=dict(color="#8C99B4"),
    )

    # severity-named traces always use the severity colours
    for trace in fig.data:

        name = getattr(trace, "name", None)

        if name in SEVERITY_COLORS and trace.type in ("bar", "scatter"):

            if trace.type == "bar":
                trace.marker.color = SEVERITY_COLORS[name]
            else:
                trace.line.color = SEVERITY_COLORS[name]

    return fig


def plotly_chart(fig, **kwargs):
    kwargs.setdefault("use_container_width", True)

    try:
        fig = style_fig(fig)
    except Exception:
        pass

    return st.plotly_chart(fig, **kwargs)


# ---------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------

def sidebar_brand():
    st.sidebar.markdown(
        '<div class="nx-brand"><div class="nx-brand-logo">🛡️</div>'
        '<div><div class="nx-brand-name">NIDRS</div>'
        '<div class="nx-brand-tag">Intrusion Detection &amp; Response</div></div></div>'
        '<div class="nx-side-label">Navigation</div>',
        unsafe_allow_html=True,
    )


def monitor_status(lock_file):
    """(is_running, info_dict) from the continuous monitor's lock file."""

    lock_file = Path(lock_file)

    if not lock_file.exists():
        return False, {}

    try:
        lines = lock_file.read_text().strip().split("\n")

        info = dict(line.split("=", 1) for line in lines if "=" in line)

        beat = datetime.fromisoformat(info["last_heartbeat"])

        return (datetime.now() - beat).total_seconds() < 30, info

    except Exception:
        return False, {}


def sidebar_status(alert_count, last_alert, monitor_running):
    last = (
        last_alert.strftime("%d %b, %H:%M")
        if isinstance(last_alert, (pd.Timestamp, datetime)) and not pd.isna(last_alert)
        else "—"
    )

    monitor = (
        '<span style="color:#86EFAC">● Running</span>'
        if monitor_running
        else '<span style="color:#8C99B4">○ Idle</span>'
    )

    st.sidebar.markdown(
        '<div class="nx-side-label">System status</div>'
        '<div class="nx-side-card">'
        f'<div class="nx-side-row"><span>Monitor</span><span>{monitor}</span></div>'
        f'<div class="nx-side-row"><span>Stored alerts</span><span>{int(alert_count)}</span></div>'
        f'<div class="nx-side-row"><span>Last alert</span><span>{escape(last)}</span></div>'
        '<div class="nx-side-row"><span>Auto-refresh</span><span>5 s</span></div>'
        "</div>",
        unsafe_allow_html=True,
    )


def sidebar_user(username):
    initial = (str(username)[:1] or "A").upper()

    st.sidebar.markdown(
        '<div class="nx-side-label">Account</div>'
        f'<div class="nx-user"><div class="nx-avatar">{escape(initial)}</div>'
        f'<div><div class="nx-user-name">{escape(str(username))}</div>'
        '<div class="nx-user-role">Security Analyst</div></div></div>',
        unsafe_allow_html=True,
    )

    return st.sidebar.button("Log out", use_container_width=True)


# ---------------------------------------------------------------
# LOGIN
# ---------------------------------------------------------------

def login_header():
    _html("""
    <div class="nx-login">
      <div class="nx-brand-logo">🛡️</div>
      <div class="nx-login-title">NIDRS</div>
      <div class="nx-login-sub">AI-Powered Network Intrusion Detection &amp; Response System</div>
    </div>
    """)
