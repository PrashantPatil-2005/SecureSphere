#!/usr/bin/env python3
# =============================================================================
# SecuriSphere — Phase 4: Custom CSS Styles
# =============================================================================
"""
All custom CSS for the Streamlit dashboard is defined here as Python strings.
These are injected into the page via st.markdown(css, unsafe_allow_html=True).

Design Tokens:
    Low     → #10B981 (green)
    Medium  → #F59E0B (amber)
    High    → #EF4444 (red)
    Critical→ #B91C1C (dark red)
    Background → dark theme (Streamlit native dark mode)

The goal is a modern, enterprise SIEM-like look with glassmorphism cards,
smooth animations, and clear severity color coding.
"""

# =============================================================================
# Severity Color Map (used in Python logic too)
# =============================================================================
SEVERITY_COLORS = {
    "info":     "#6B7280",   # gray
    "low":      "#10B981",   # green
    "medium":   "#F59E0B",   # amber
    "high":     "#EF4444",   # red
    "critical": "#B91C1C",   # dark red
}

# =============================================================================
# Main CSS — injected once at app startup
# =============================================================================
MAIN_CSS = """
<style>
/* ============================================================
   GLOBAL OVERRIDES
   ============================================================ */

/* Import professional font */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');

/* Apply Inter everywhere */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
}

/* Remove Streamlit's default padding for wider feel */
.block-container {
    padding-top: 1rem !important;
    padding-bottom: 1rem !important;
    max-width: 100% !important;
}

/* ============================================================
   HEADER / TITLE BRANDING
   ============================================================ */
.main-title {
    font-size: 2.4rem;
    font-weight: 800;
    background: linear-gradient(135deg, #3B82F6, #8B5CF6, #EC4899);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0;
    letter-spacing: -0.5px;
}

.sub-title {
    font-size: 0.95rem;
    color: #9CA3AF;
    margin-top: -8px;
    font-weight: 400;
    letter-spacing: 0.5px;
}

/* ============================================================
   SIDEBAR BRANDING
   ============================================================ */
.sidebar-brand {
    text-align: center;
    padding: 1rem 0 0.5rem 0;
}
.sidebar-brand h2 {
    font-size: 1.4rem;
    font-weight: 800;
    background: linear-gradient(135deg, #3B82F6, #8B5CF6);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 2px;
}
.sidebar-tagline {
    font-size: 0.7rem;
    color: #9CA3AF;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    margin-bottom: 1rem;
}

/* ============================================================
   METRIC CARDS — glassmorphism style
   ============================================================ */
.metric-card {
    background: linear-gradient(135deg, rgba(30,41,59,0.8), rgba(15,23,42,0.9));
    border: 1px solid rgba(99,102,241,0.2);
    border-radius: 16px;
    padding: 1.2rem 1.5rem;
    text-align: center;
    backdrop-filter: blur(10px);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
    box-shadow: 0 4px 15px rgba(0,0,0,0.3);
}
.metric-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(99,102,241,0.2);
}
.metric-card .metric-value {
    font-size: 2.2rem;
    font-weight: 800;
    color: #F1F5F9;
    line-height: 1.1;
}
.metric-card .metric-label {
    font-size: 0.8rem;
    color: #94A3B8;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 4px;
}
.metric-card .metric-delta {
    font-size: 0.75rem;
    margin-top: 4px;
}
.metric-delta.up   { color: #EF4444; }
.metric-delta.down { color: #10B981; }

/* ============================================================
   SEVERITY BADGES
   ============================================================ */
.badge {
    display: inline-block;
    padding: 3px 12px;
    border-radius: 999px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}
.badge-info     { background: #374151; color: #9CA3AF; }
.badge-low      { background: rgba(16,185,129,0.15); color: #10B981; border: 1px solid rgba(16,185,129,0.3); }
.badge-medium   { background: rgba(245,158,11,0.15); color: #F59E0B; border: 1px solid rgba(245,158,11,0.3); }
.badge-high     { background: rgba(239,68,68,0.15); color: #EF4444; border: 1px solid rgba(239,68,68,0.3); }
.badge-critical { background: rgba(185,28,28,0.2); color: #FCA5A5; border: 1px solid rgba(185,28,28,0.4); }

/* Large badge variant for incident cards */
.badge-lg {
    padding: 6px 20px;
    font-size: 0.85rem;
    letter-spacing: 1px;
}

/* ============================================================
   INCIDENT CARDS (Correlated Incidents tab)
   ============================================================ */
.incident-card {
    background: linear-gradient(135deg, rgba(30,41,59,0.7), rgba(15,23,42,0.85));
    border: 1px solid rgba(99,102,241,0.15);
    border-radius: 16px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 4px 15px rgba(0,0,0,0.2);
}
.incident-card.critical {
    border-left: 4px solid #B91C1C;
}
.incident-card.high {
    border-left: 4px solid #EF4444;
}
.incident-card.medium {
    border-left: 4px solid #F59E0B;
}
.incident-card .incident-title {
    font-size: 1.15rem;
    font-weight: 700;
    color: #F1F5F9;
    margin-bottom: 8px;
}
.incident-card .incident-story {
    color: #CBD5E1;
    font-size: 0.88rem;
    line-height: 1.6;
    margin: 0.8rem 0;
}

/* ============================================================
   THREAT MAP CARDS (Overview tab)
   ============================================================ */
.threat-card {
    background: linear-gradient(135deg, rgba(185,28,28,0.08), rgba(30,41,59,0.6));
    border: 1px solid rgba(185,28,28,0.25);
    border-radius: 12px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.6rem;
}
.threat-card .threat-title {
    font-weight: 600;
    color: #FCA5A5;
    font-size: 0.9rem;
}
.threat-card .threat-detail {
    color: #94A3B8;
    font-size: 0.8rem;
    margin-top: 4px;
}

/* ============================================================
   PULSING "LIVE" INDICATOR
   ============================================================ */
@keyframes pulse {
    0%   { opacity: 1; box-shadow: 0 0 0 0 rgba(239,68,68,0.7); }
    70%  { opacity: 1; box-shadow: 0 0 0 10px rgba(239,68,68,0); }
    100% { opacity: 1; box-shadow: 0 0 0 0 rgba(239,68,68,0); }
}

.live-indicator {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(239,68,68,0.15);
    border: 1px solid rgba(239,68,68,0.3);
    border-radius: 999px;
    padding: 4px 14px;
    font-size: 0.7rem;
    font-weight: 700;
    color: #EF4444;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.live-dot {
    width: 8px;
    height: 8px;
    background: #EF4444;
    border-radius: 50%;
    animation: pulse 2s infinite;
}

/* ============================================================
   TAB STYLING OVERRIDES
   ============================================================ */
.stTabs [data-baseweb="tab-list"] {
    gap: 4px;
    background: rgba(15,23,42,0.5);
    border-radius: 12px;
    padding: 4px;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 8px;
    padding: 8px 20px;
    font-weight: 500;
    font-size: 0.85rem;
}
.stTabs [aria-selected="true"] {
    background: rgba(99,102,241,0.15) !important;
    border-bottom-color: #6366F1 !important;
}

/* ============================================================
   RISK TABLE ROW COLORING (injected per-row via inline styles)
   ============================================================ */
.risk-critical { background: rgba(185,28,28,0.15) !important; }
.risk-high     { background: rgba(239,68,68,0.10) !important; }
.risk-medium   { background: rgba(245,158,11,0.10) !important; }
.risk-low      { background: rgba(16,185,129,0.08) !important; }

/* ============================================================
   SCROLLBAR STYLING (subtle)
   ============================================================ */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #374151; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #4B5563; }

/* ============================================================
   CORRELATION TOGGLE (Before vs After)
   ============================================================ */
.correlation-before {
    background: rgba(245,158,11,0.08);
    border: 1px solid rgba(245,158,11,0.2);
    border-radius: 12px;
    padding: 1rem;
}
.correlation-after {
    background: rgba(99,102,241,0.08);
    border: 1px solid rgba(99,102,241,0.2);
    border-radius: 12px;
    padding: 1rem;
}
.correlation-label {
    font-weight: 700;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
}
.correlation-before .correlation-label { color: #F59E0B; }
.correlation-after  .correlation-label { color: #818CF8; }
</style>
"""


def inject_css():
    """Call this once at app startup to inject all custom CSS."""
    import streamlit as st
    st.markdown(MAIN_CSS, unsafe_allow_html=True)
