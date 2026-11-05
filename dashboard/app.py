"""
SENTINEL — OS SECURITY MONITORING
Enterprise Security Analytics Dashboard
Entry point for the Streamlit presentation tier.
"""

from __future__ import annotations

from pathlib import Path
import streamlit as st

# ── 1. Page Configuration (Must be very first Streamlit call) ─────────────────
st.set_page_config(
    page_title="SENTINEL // OS Security Monitoring",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── 2. Backend & Component Imports ────────────────────────────────────────────
from monitor.controller import SentinelController
from monitor.event_models import SourceType
from dashboard.theme import get_app_css
from dashboard.components import render_top_navbar
from dashboard.views.overview import render_overview
from dashboard.views.events import render_events
from dashboard.views.threats import render_threats
from dashboard.views.investigations import render_investigations
from dashboard.views.analytics import render_analytics
from dashboard.views.system import render_system

# ── 3. Controller Singleton (Survives reruns via @st.cache_resource) ──────────
_ROOT = Path(__file__).resolve().parent.parent
_CHECKPOINT = _ROOT / "data" / ".checkpoint.json"
_INCIDENTS = _ROOT / "data" / "incidents_history.json"

@st.cache_resource
def _get_controller() -> SentinelController:
    """Instantiate single SentinelController instance for application lifecycle."""
    return SentinelController(
        channels=["System", "Application"],
        poll_interval=2.0,
        detection_threshold=3,
        window_seconds=60,
        checkpoint_path=_CHECKPOINT,
        incident_storage_path=_INCIDENTS,
        source_type=SourceType.STATIC_SAMPLE_FILE,
    )

ctrl = _get_controller()

# ── 4. Session State Initialization ───────────────────────────────────────────
if "page" not in st.session_state:
    st.session_state.page = "Overview"

# Theme state default: "dark" (supports "dark" and "light")
if "theme" not in st.session_state:
    st.session_state.theme = "dark"

# Backward-compatibility key for test_sidebar_state_defaults_and_toggle
if "sidebar_expanded" not in st.session_state:
    st.session_state.sidebar_expanded = False

if "initial_load_done" not in st.session_state:
    ctrl.set_source_type(SourceType.STATIC_SAMPLE_FILE)
    ctrl.run_once()
    st.session_state.initial_load_done = True

if "feedback_msg" not in st.session_state:
    st.session_state.feedback_msg = None

# ── 5. Inject CSS Stylesheet dynamically for active theme ─────────────────────
active_theme = st.session_state.get("theme", "dark")
st.markdown(get_app_css(active_theme), unsafe_allow_html=True)

# ── 6. Render Top Horizontal Navigation Bar ───────────────────────────────────
render_top_navbar(ctrl)

# ── 7. Route to Active Page View ──────────────────────────────────────────────
page = st.session_state.get("page", "Overview")

page_alias_map = {
    "Event Stream": "Events",
    "Log Explorer": "Events",
    "Threat Detection": "Threats",
}
resolved_page = page_alias_map.get(page, page)

if resolved_page == "Overview":
    render_overview(ctrl)
elif resolved_page == "Events":
    render_events(ctrl)
elif resolved_page == "Threats":
    render_threats(ctrl)
elif resolved_page == "Investigations":
    render_investigations(ctrl)
elif resolved_page == "Analytics":
    render_analytics(ctrl)
elif resolved_page == "System":
    render_system(ctrl)
else:
    st.session_state.page = "Overview"
    render_overview(ctrl)
