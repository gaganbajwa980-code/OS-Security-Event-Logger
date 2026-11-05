"""
SENTINEL — Enterprise Design System & Dual-Theme System
Defines complete Color Palettes for Light (Enterprise Security Analytics)
and Dark (Premium SOC Command Centre), dynamic CSS injection, and Plotly theme.
"""

from __future__ import annotations

from typing import Any
import plotly.graph_objects as go

# ══════════════════════════════════════════════════════════════════════════════
# THEME PALETTES
# ══════════════════════════════════════════════════════════════════════════════

THEMES: dict[str, dict[str, str]] = {
    # ── Light Theme: Enterprise Security Analytics ────────────────────────────
    "light": {
        "main_bg": "#F4F7FB",
        "nav_bg": "#FFFFFF",          # Clean crisp light navbar for light mode
        "secondary_surface": "#F8FAFD",
        "card_bg": "#FFFFFF",
        "elevated_surface": "#F1F5FB",
        "text_primary": "#172B4D",
        "text_secondary": "#52647A",
        "text_muted": "#718096",
        "border": "#DCE4EE",
        "border_subtle": "#EDF2F7",
        "primary_blue": "#2563EB",
        "ice_blue": "#60A5FA",
        "success": "#16865D",
        "warning": "#C98516",
        "critical": "#D64550",
        "info": "#2878C7",
        "brand_wordmark": "#172B4D",
        "brand_subtitle": "#2878C7",
        "kpi_shadow": "0 1px 3px rgba(0,0,0,0.05)",
        "card_shadow": "0 1px 3px rgba(0,0,0,0.04)",
        "hover_bg": "#E9F2FE",
        "table_header_bg": "#F8FAFD",
        "table_row_alt": "#FAFCFF",
    },
    # ── Dark Theme: Premium SOC Command Centre ────────────────────────────────
    "dark": {
        "main_bg": "#0B1220",
        "nav_bg": "#080F1C",          # Deep slate charcoal navbar
        "secondary_surface": "#111C2E",
        "card_bg": "#162338",
        "elevated_surface": "#1C2D45",
        "text_primary": "#E8F0FC",
        "text_secondary": "#9BAEC8",
        "text_muted": "#7185A3",
        "border": "#263A55",
        "border_subtle": "#1E2F46",
        "primary_blue": "#4D9FFF",
        "ice_blue": "#82C5FF",
        "success": "#35C98A",
        "warning": "#F3B64B",
        "critical": "#FF6978",
        "info": "#66B3FF",
        "brand_wordmark": "#F1F5FB",
        "brand_subtitle": "#7DBBFF",
        "kpi_shadow": "0 2px 6px rgba(0,0,0,0.25)",
        "card_shadow": "0 2px 8px rgba(0,0,0,0.20)",
        "hover_bg": "#1E304B",
        "table_header_bg": "#111C2E",
        "table_row_alt": "#142033",
    },
}

# Backward-compatibility default aliases (Dark theme defaults)
COLOR_MAIN_BG   = THEMES["dark"]["main_bg"]
COLOR_PANEL_BG  = THEMES["dark"]["card_bg"]
COLOR_NAV_BG    = THEMES["dark"]["nav_bg"]
COLOR_PRIMARY   = THEMES["dark"]["primary_blue"]
COLOR_ICE_BLUE  = THEMES["dark"]["ice_blue"]
COLOR_TEXT_PRI  = THEMES["dark"]["text_primary"]
COLOR_TEXT_SEC  = THEMES["dark"]["text_secondary"]
COLOR_BORDER    = THEMES["dark"]["border"]
COLOR_SUCCESS   = THEMES["dark"]["success"]
COLOR_WARNING   = THEMES["dark"]["warning"]
COLOR_CRITICAL  = THEMES["dark"]["critical"]


def get_theme(theme_name: str = "dark") -> dict[str, str]:
    """Retrieve color palette dictionary for active theme ('light' or 'dark')."""
    return THEMES.get(theme_name.lower(), THEMES["dark"])


def get_app_css(theme_name: str = "dark") -> str:
    """Generate comprehensive CSS tailored for active theme."""
    t = get_theme(theme_name)
    is_dark = (theme_name.lower() == "dark")

    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

/* ── Streamlit internal CSS variables bridge ─────── */
:root {{
    --text-color: {t['text_primary']} !important;
    --background-color: {t['main_bg']} !important;
    --secondary-background-color: {t['card_bg']} !important;
    --primary-color: {t['primary_blue']} !important;
}}

/* ── Base resets & global typography ─────────────── */
html, body, [class*="css"] {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    font-size: 13px;
    color: {t['text_primary']} !important;
    -webkit-font-smoothing: antialiased;
}}

/* ── Canvas background ───────────────────────────── */
.stApp {{
    background-color: {t['main_bg']} !important;
    color: {t['text_primary']} !important;
}}

/* ── Completely remove Streamlit left sidebar & header ── */
[data-testid="stSidebar"], section[data-testid="stSidebar"] {{
    display: none !important;
    width: 0 !important;
    min-width: 0 !important;
    max-width: 0 !important;
}}
[data-testid="stSidebarNav"] {{ display: none !important; }}
[data-testid="stHeader"] {{ display: none !important; }}
[data-testid="stToolbar"] {{ display: none !important; }}
footer {{ display: none !important; }}

/* ── Full width container layout ─────────────────── */
.block-container {{
    padding-top: 0 !important;
    padding-bottom: 2rem !important;
    padding-left: 1.25rem !important;
    padding-right: 1.25rem !important;
    max-width: 100% !important;
}}

/* ── Typography helpers ──────────────────────────── */
.mono {{
    font-family: 'JetBrains Mono', 'Consolas', monospace !important;
    font-size: 11.5px !important;
    letter-spacing: -0.01em;
}}

/* ── Custom Scrollbars ───────────────────────────── */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: {t['main_bg']}; }}
::-webkit-scrollbar-thumb {{ background: {t['border']}; border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: {t['primary_blue']}; }}

/* ── Top Horizontal Navigation Bar Container ─────── */
div:has(> div.st-key-top_navbar),
div:has(> div[class*="st-key-top_navbar"]),
div.st-key-top_navbar,
div[class*="st-key-top_navbar"] {{
    background-color: {t['nav_bg']} !important;
    border-bottom: 1px solid {t['border']} !important;
    border-top: none !important;
    border-left: none !important;
    border-right: none !important;
    border-radius: 0 !important;
    box-shadow: {'0 2px 8px rgba(0,0,0,0.06)' if not is_dark else '0 2px 8px rgba(0,0,0,0.35)'} !important;
    padding: 8px 16px !important;
    margin-left: -1.25rem !important;
    margin-right: -1.25rem !important;
    margin-top: 0 !important;
    margin-bottom: 6px !important;
}}

/* ── Secondary Context Sub-Navigation Bar ─────────── */
div:has(> div.st-key-secondary_nav),
div:has(> div[class*="st-key-secondary_nav"]),
div.st-key-secondary_nav,
div[class*="st-key-secondary_nav"] {{
    background-color: {t['secondary_surface']} !important;
    border-bottom: 1px solid {t['border']} !important;
    border-top: none !important;
    border-left: none !important;
    border-right: none !important;
    border-radius: 0 !important;
    box-shadow: none !important;
    padding: 5px 16px !important;
    margin-left: -1.25rem !important;
    margin-right: -1.25rem !important;
    margin-bottom: 12px !important;
}}

/* ── Compact Monitoring Toolbar Container ────────── */
div:has(> div.st-key-monitoring_toolbar),
div:has(> div[class*="st-key-monitoring_toolbar"]),
div.st-key-monitoring_toolbar,
div[class*="st-key-monitoring_toolbar"] {{
    background-color: {t['card_bg']} !important;
    border: 1px solid {t['border']} !important;
    border-radius: 6px !important;
    box-shadow: {t['card_shadow']} !important;
    padding: 8px 14px !important;
    margin-bottom: 14px !important;
}}

/* ── Universal Card Container (st.container border=True) ── */
div[data-testid="stVerticalBlockBorderWrapper"],
div[data-testid="stContainer"][data-test-scroll-behavior="normal"] {{
    background-color: {t['card_bg']} !important;
    border: 1px solid {t['border']} !important;
    border-radius: 6px !important;
    box-shadow: {t['card_shadow']} !important;
}}

div[data-testid="stVerticalBlockBorderWrapper"] > div {{
    padding: 12px 14px !important;
    gap: 8px !important;
}}

/* Prevent toolbar and navbars from inheriting nested card padding */
div.st-key-top_navbar > div[data-testid="stVerticalBlockBorderWrapper"],
div.st-key-secondary_nav > div[data-testid="stVerticalBlockBorderWrapper"],
div.st-key-monitoring_toolbar > div[data-testid="stVerticalBlockBorderWrapper"] {{
    border: none !important;
    box-shadow: none !important;
    background: transparent !important;
    padding: 0 !important;
}}

/* ── KPI Metric Cards ────────────────────────────── */
.sentinel-kpi-card {{
    background-color: {t['card_bg']};
    border: 1px solid {t['border']};
    border-radius: 6px;
    padding: 12px 14px;
    box-shadow: {t['kpi_shadow']};
    height: 100%;
    min-height: 85px;
    position: relative;
    overflow: hidden;
}}
.sentinel-kpi-card::before {{
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
}}
.kpi-accent-blue::before {{ background: {t['primary_blue']}; }}
.kpi-accent-green::before {{ background: {t['success']}; }}
.kpi-accent-amber::before {{ background: {t['warning']}; }}
.kpi-accent-red::before {{ background: {t['critical']}; }}
.kpi-accent-ice::before {{ background: {t['ice_blue']}; }}

.sentinel-kpi-title {{
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: {t['text_secondary']};
    margin-bottom: 4px;
}}
.sentinel-kpi-value {{
    font-size: 24px;
    font-weight: 700;
    color: {t['text_primary']};
    font-family: 'JetBrains Mono', monospace;
    line-height: 1.1;
    margin-bottom: 3px;
}}
.sentinel-kpi-sub {{
    font-size: 11px;
    color: {t['text_secondary']};
}}

/* ── Analytical Card & Panel Containers ──────────── */
.sentinel-card {{
    background-color: {t['card_bg']};
    border: 1px solid {t['border']};
    border-radius: 6px;
    padding: 14px 16px;
    margin-bottom: 14px;
    box-shadow: {t['card_shadow']};
}}
.sentinel-card-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 8px;
    margin-bottom: 10px;
    border-bottom: 1px solid {t['border_subtle']};
}}
.sentinel-card-title {{
    font-size: 12.5px;
    font-weight: 700;
    letter-spacing: 0.03em;
    color: {t['text_primary']};
    display: flex;
    align-items: center;
    gap: 8px;
}}
.sentinel-card-badge {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 9.5px;
    font-weight: 600;
    color: {t['text_secondary']};
    background-color: {t['elevated_surface']};
    border: 1px solid {t['border']};
    border-radius: 3px;
    padding: 2px 6px;
}}

/* ── Badges & Status Indicators ──────────────────── */
.status-pill {{
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 10px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    padding: 2px 8px;
    border-radius: 4px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}}
.pill-running {{ color: {t['success']} !important; background: {'rgba(22,134,93,0.12)' if not is_dark else 'rgba(53,201,138,0.14)'} !important; border: 1px solid {t['success']} !important; }}
.pill-paused  {{ color: {t['warning']} !important; background: {'rgba(201,133,22,0.12)' if not is_dark else 'rgba(243,182,75,0.14)'} !important; border: 1px solid {t['warning']} !important; }}
.pill-idle    {{ color: {t['text_secondary']} !important; background: {t['elevated_surface']} !important; border: 1px solid {t['border']} !important; }}
.pill-error   {{ color: {t['critical']} !important; background: {'rgba(214,69,80,0.12)' if not is_dark else 'rgba(255,105,120,0.14)'} !important; border: 1px solid {t['critical']} !important; }}

/* Severity Badges */
.sev-badge {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 9.5px;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 4px;
    text-transform: uppercase;
    display: inline-block;
    letter-spacing: 0.04em;
}}
.sev-critical {{ color: #FFFFFF !important; background: {t['critical']} !important; }}
.sev-high     {{ color: #FFFFFF !important; background: #E67E22 !important; }}
.sev-warning  {{ color: #172B4D !important; background: {t['warning']} !important; }}
.sev-info     {{ color: {t['text_secondary']} !important; background: {t['elevated_surface']} !important; border: 1px solid {t['border']} !important; }}

/* Source Type Badges */
.src-badge {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 9.5px;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 4px;
    display: inline-block;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}}
.src-live   {{ color: {t['success']} !important; background: {'rgba(22,134,93,0.12)' if not is_dark else 'rgba(53,201,138,0.14)'} !important; border: 1px solid {t['success']} !important; }}
.src-sim    {{ color: {t['warning']} !important; background: {'rgba(201,133,22,0.12)' if not is_dark else 'rgba(243,182,75,0.14)'} !important; border: 1px solid {t['warning']} !important; }}
.src-sample {{ color: {t['primary_blue']} !important; background: {'rgba(37,99,235,0.10)' if not is_dark else 'rgba(77,159,255,0.14)'} !important; border: 1px solid {t['primary_blue']} !important; }}

/* ── Hardware & Telemetry Metrics (st.metric) ────── */
div[data-testid="stMetric"],
div[data-testid="stMetric"] * {{
    background-color: transparent !important;
}}
div[data-testid="stMetricLabel"],
div[data-testid="stMetricLabel"] *,
div[data-testid="stMetricLabel"] p {{
    color: {t['text_secondary']} !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    letter-spacing: 0.04em !important;
    text-transform: uppercase !important;
}}
div[data-testid="stMetricValue"],
div[data-testid="stMetricValue"] * {{
    color: {t['text_primary']} !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 21px !important;
    font-weight: 700 !important;
}}
div[data-testid="stMetricDelta"],
div[data-testid="stMetricDelta"] * {{
    font-family: 'Inter', sans-serif !important;
    font-size: 11px !important;
    font-weight: 600 !important;
}}

/* ── Streamlit Native Buttons & Download Buttons ─── */
.stApp button,
button,
button[data-testid="baseButton-secondary"],
button[data-testid="baseButton-primary"],
div[data-testid="stButton"] button,
div.stButton button,
div[class*="st-key-"] button,
div.stDownloadButton button {{
    background-color: {t['elevated_surface']} !important;
    color: {t['text_primary']} !important;
    border: 1px solid {t['border']} !important;
    border-radius: 4px !important;
    font-size: 12px !important;
    font-weight: 500 !important;
    padding: 4px 10px !important;
    box-shadow: none !important;
    transition: all 0.15s ease !important;
}}

.stApp button *,
button *,
button[data-testid="baseButton-secondary"] *,
div[data-testid="stButton"] button *,
div.stButton button *,
div.stDownloadButton button * {{
    color: {t['text_primary']} !important;
    font-size: 12px !important;
    font-weight: 500 !important;
}}

/* Secondary Button Hover */
.stApp button[data-testid="baseButton-secondary"]:hover,
div[data-testid="stButton"] button[data-testid="baseButton-secondary"]:hover,
button[data-testid="baseButton-secondary"]:hover,
div.stButton button:hover,
div.stDownloadButton button:hover {{
    border-color: {t['primary_blue']} !important;
    color: {t['primary_blue']} !important;
    background-color: {t['hover_bg']} !important;
}}

.stApp button[data-testid="baseButton-secondary"]:hover *,
div[data-testid="stButton"] button[data-testid="baseButton-secondary"]:hover *,
button[data-testid="baseButton-secondary"]:hover *,
div.stButton button:hover *,
div.stDownloadButton button:hover * {{
    color: {t['primary_blue']} !important;
}}

.stApp button:active,
button:active {{
    background-color: {t['elevated_surface']} !important;
}}

/* Disabled Buttons */
.stApp button:disabled,
button:disabled,
button[disabled],
button[data-testid="baseButton-secondary"]:disabled,
button[data-testid="baseButton-primary"]:disabled,
div[data-testid="stButton"] button:disabled {{
    opacity: 0.38 !important;
    cursor: not-allowed !important;
    border-color: {t['border_subtle']} !important;
    background-color: {t['elevated_surface']} !important;
    color: {t['text_muted']} !important;
}}

.stApp button:disabled *,
button:disabled *,
button[disabled] *,
div[data-testid="stButton"] button:disabled * {{
    color: {t['text_muted']} !important;
}}

/* Primary Buttons (Active Nav Tab, Action Buttons) */
.stApp button[data-testid="baseButton-primary"],
button[data-testid="baseButton-primary"],
button[kind="primary"],
div[data-testid="stButton"] button[data-testid="baseButton-primary"],
div.stButton button[kind="primary"],
div.stDownloadButton button[kind="primary"] {{
    background-color: {t['primary_blue']} !important;
    color: #FFFFFF !important;
    border-color: {t['primary_blue']} !important;
    font-weight: 600 !important;
}}

.stApp button[data-testid="baseButton-primary"] *,
button[data-testid="baseButton-primary"] *,
div[data-testid="stButton"] button[data-testid="baseButton-primary"] *,
div.stButton button[kind="primary"] * {{
    color: #FFFFFF !important;
    font-weight: 600 !important;
}}

.stApp button[data-testid="baseButton-primary"]:hover,
button[data-testid="baseButton-primary"]:hover,
div[data-testid="stButton"] button[data-testid="baseButton-primary"]:hover {{
    background-color: {t['ice_blue']} !important;
    border-color: {t['ice_blue']} !important;
    color: #FFFFFF !important;
}}

/* Explicit Navigation & Control Button Refinements */
div.st-key-top_navbar button {{
    font-size: 11.5px !important;
    padding: 3px 6px !important;
    white-space: nowrap !important;
}}

div.st-key-btn_theme_toggle button,
div.st-key-btn_theme_toggle button[data-testid="baseButton-secondary"],
div.st-key-nav_quick_refresh button,
div.st-key-nav_quick_refresh button[data-testid="baseButton-secondary"] {{
    background-color: {t['elevated_surface']} !important;
    border: 1px solid {t['border']} !important;
    color: {t['text_primary']} !important;
    font-weight: 600 !important;
}}

div.st-key-btn_theme_toggle button *,
div.st-key-nav_quick_refresh button * {{
    color: {t['text_primary']} !important;
}}

/* ── Form inputs & Selectboxes ───────────────────── */
input, select, textarea {{
    background-color: {t['elevated_surface']} !important;
    color: {t['text_primary']} !important;
    border: 1px solid {t['border']} !important;
    border-radius: 4px !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 12px !important;
}}
div[data-testid="stTextInput"] input {{
    background-color: {t['elevated_surface']} !important;
    color: {t['text_primary']} !important;
    border: 1px solid {t['border']} !important;
}}
div[data-baseweb="select"] {{
    background-color: transparent !important;
}}
div[data-baseweb="select"] > div {{
    background-color: {t['elevated_surface']} !important;
    border-color: {t['border']} !important;
    color: {t['text_primary']} !important;
}}
div[data-baseweb="select"] span,
div[data-baseweb="select"] div,
div[data-baseweb="select"] input {{
    color: {t['text_primary']} !important;
}}
div[data-baseweb="select"] svg {{
    fill: {t['text_secondary']} !important;
}}
div[data-baseweb="popover"],
div[data-baseweb="menu"],
ul[role="listbox"] {{
    background-color: {t['card_bg']} !important;
    border: 1px solid {t['border']} !important;
    color: {t['text_primary']} !important;
}}
li[role="option"] {{
    background-color: {t['card_bg']} !important;
    color: {t['text_primary']} !important;
}}
li[role="option"]:hover,
li[aria-selected="true"] {{
    background-color: {t['hover_bg']} !important;
    color: {t['primary_blue']} !important;
}}
div[data-baseweb="tag"] {{
    background-color: {t['elevated_surface']} !important;
    border: 1px solid {t['border']} !important;
    color: {t['text_primary']} !important;
}}
div[data-baseweb="tag"] span {{
    color: {t['text_primary']} !important;
}}

/* ── Sliders ─────────────────────────────────────── */
div[data-testid="stSlider"] label,
div[data-testid="stSlider"] span,
div[data-testid="stSlider"] div {{
    color: {t['text_secondary']} !important;
}}

/* ── DataFrames Styling ──────────────────────────── */
div[data-testid="stDataFrame"] {{
    background-color: {t['card_bg']} !important;
    border: 1px solid {t['border']} !important;
    border-radius: 6px !important;
    overflow: hidden !important;
}}

/* ── Expanders ───────────────────────────────────── */
div[data-testid="stExpander"] {{
    background-color: {t['elevated_surface']} !important;
    border: 1px solid {t['border']} !important;
    border-radius: 6px !important;
    color: {t['text_primary']} !important;
}}
div[data-testid="stExpander"] summary {{
    color: {t['text_primary']} !important;
    font-weight: 600 !important;
}}

/* ── Feedback and notification banner ────────────── */
.sentinel-feedback {{
    background-color: {t['elevated_surface']};
    border: 1px solid {t['primary_blue']};
    color: {t['primary_blue']};
    padding: 8px 12px;
    border-radius: 5px;
    font-size: 11.5px;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
}}

div[data-testid="stAlert"] {{
    background-color: {t['elevated_surface']} !important;
    border: 1px solid {t['border']} !important;
    color: {t['text_primary']} !important;
}}
div[data-testid="stAlert"] p {{
    color: {t['text_primary']} !important;
}}
</style>
"""


def apply_plotly_theme(fig: go.Figure, theme_name: str = "dark", height: int = 220) -> go.Figure:
    """Apply uniform enterprise theme (Dark or Light) to Plotly figures."""
    t = get_theme(theme_name)
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family="Inter, -apple-system, sans-serif",
            size=11,
            color=t["text_primary"],
        ),
        margin=dict(l=30, r=20, t=25, b=25),
        height=height,
        hoverlabel=dict(
            bgcolor=t["card_bg"],
            bordercolor=t["border"],
            font=dict(
                family="Inter, -apple-system, sans-serif",
                size=11,
                color=t["text_primary"],
            ),
        ),
        xaxis=dict(
            showgrid=True,
            gridcolor=t["border_subtle"],
            gridwidth=1,
            linecolor=t["border"],
            tickfont=dict(family="JetBrains Mono, monospace", size=9.5, color=t["text_secondary"]),
            title=dict(font=dict(color=t["text_secondary"], size=10)),
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor=t["border_subtle"],
            gridwidth=1,
            linecolor=t["border"],
            tickfont=dict(family="JetBrains Mono, monospace", size=9.5, color=t["text_secondary"]),
            title=dict(font=dict(color=t["text_secondary"], size=10)),
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=10, color=t["text_secondary"]),
        ),
    )
    # Ensure pie charts have legible text colors matching theme
    fig.update_traces(
        selector=dict(type="pie"),
        textfont=dict(color=t["text_primary"], family="Inter, sans-serif"),
    )
    return fig


# Backward-compatible alias for older imports
apply_plotly_light_theme = apply_plotly_theme
