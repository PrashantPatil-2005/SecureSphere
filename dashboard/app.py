#!/usr/bin/env python3
# =============================================================================
# SecuriSphere — Phase 4: Unified Professional Dashboard
# =============================================================================
"""
Main Streamlit application for the SecuriSphere cybersecurity monitoring platform.

This dashboard provides a single-pane-of-glass view across all three security
layers (Network, Password, API) and — most importantly — shows how CORRELATION
turns scattered medium alerts into prioritized, high-severity incidents.

Run with:
    cd securesphere
    streamlit run dashboard/app.py

Tabs:
    1. Overview Dashboard  — Metrics, risk gauge, live threat map
    2. Network Timeline    — Anomaly timeline with baseline
    3. Password Compliance — Compliance gauge, violations table, pie chart
    4. API Vulnerabilities — OWASP-categorized vulnerability table + bar chart
    5. Correlated Incidents— THE KEY TAB: correlation magic, incident cards
    6. Risk Prioritization — Ranked asset risk table with heatmap coloring
"""

import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Local imports — our custom modules
from dashboard.styles import SEVERITY_COLORS, inject_css
from dashboard.utils import (
    check_backend_health,
    compute_compliance_score,
    compute_password_compliance,
    compute_api_compliance,
    compute_risk_score,
    export_incidents_csv,
    fetch_alerts,
    fetch_incidents,
    fetch_stats,
    format_timestamp,
    generate_pdf_report,
    get_alert_by_id,
    inject_attack_alerts,
    severity_badge_html,
    severity_color,
)


# =============================================================================
# PAGE CONFIGURATION — must be the very first Streamlit command
# =============================================================================
st.set_page_config(
    page_title="SecuriSphere",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject all custom CSS
inject_css()


# =============================================================================
# SIDEBAR — Branding, controls, simulation, exports
# =============================================================================

def render_sidebar():
    """
    Build the sidebar with:
        - Project branding
        - Backend health status
        - "Simulate Attack" buttons
        - Auto-refresh toggle
        - Export buttons
        - Last updated time
    """
    with st.sidebar:
        # ── Branding ────────────────────────────────────────────────────
        st.markdown("""
        <div class="sidebar-brand">
            <h2>🛡️ SecuriSphere</h2>
            <div class="sidebar-tagline">B2B Multi-Layer Cybersecurity<br>Intelligence Platform</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.divider()
        
        # ── Backend Health ──────────────────────────────────────────────
        backend_online = check_backend_health()
        if backend_online:
            st.success("🟢 Backend Online")
        else:
            st.warning("🟡 Backend Offline — Using sample data")
        
        st.divider()
        
        # ── Simulate Attack ─────────────────────────────────────────────
        # These buttons inject realistic alerts into the backend so the
        # correlation engine fires and produces incidents live.
        st.markdown("##### 🎯 Simulate Attack")
        
        scenario = st.selectbox(
            "Attack Scenario",
            options=[
                "Weak Password + Brute Force",
                "API Recon + Exploit",
                "Multi-Stage Attack",
            ],
            index=0,
            key="attack_scenario",
            help="Select an attack scenario to inject into the system"
        )
        
        # Map display names → internal keys
        scenario_map = {
            "Weak Password + Brute Force": "weak_password_bruteforce",
            "API Recon + Exploit": "api_recon_exploit",
            "Multi-Stage Attack": "multi_stage_attack",
        }
        
        if st.button("🚀 Launch Simulation", use_container_width=True, type="primary"):
            with st.spinner("Injecting attack alerts..."):
                success = inject_attack_alerts(scenario_map[scenario])
                if success:
                    st.success(f"✅ '{scenario}' simulated!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Failed — is the backend running?")
        
        st.divider()
        
        # ── Auto-Refresh Toggle ─────────────────────────────────────────
        st.markdown("##### ⚙️ Settings")
        auto_refresh = st.toggle("Auto-Refresh (8s)", value=False, key="auto_refresh")
        
        if auto_refresh:
            st.markdown(
                '<div class="live-indicator"><span class="live-dot"></span> LIVE</div>',
                unsafe_allow_html=True,
            )
        
        st.divider()
        
        # ── Export Buttons ──────────────────────────────────────────────
        st.markdown("##### 📥 Export")
        
        # We'll populate these after data is fetched — use session state
        if "incidents_data" in st.session_state and st.session_state.incidents_data:
            csv_data = export_incidents_csv(st.session_state.incidents_data)
            st.download_button(
                label="📄 Export Incidents (CSV)",
                data=csv_data,
                file_name=f"securisphere_incidents_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        
        if (
            "alerts_data" in st.session_state 
            and "incidents_data" in st.session_state
            and "stats_data" in st.session_state
        ):
            pdf_bytes = generate_pdf_report(
                st.session_state.alerts_data,
                st.session_state.incidents_data,
                st.session_state.stats_data,
            )
            st.download_button(
                label="📋 Generate PDF Report",
                data=pdf_bytes,
                file_name=f"securisphere_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        
        st.divider()
        
        # ── Last Updated ────────────────────────────────────────────────
        st.caption(f"🕐 Last updated: {datetime.now().strftime('%H:%M:%S')}")
        
        return auto_refresh


# =============================================================================
# TAB 1: OVERVIEW DASHBOARD
# =============================================================================

def render_overview(alerts, incidents, stats):
    """
    Overview tab with:
        - 4 metric cards (Active Incidents, Risk Score, Total Alerts, Compliance)
        - Plotly gauge for risk score
        - Live Threat Map (top 3 critical incidents)
    """
    # ── Row 1: Four Metric Cards ────────────────────────────────────────
    risk_score = compute_risk_score(alerts, incidents)
    compliance = compute_compliance_score(alerts)
    total_alerts = stats.get("total_alerts", len(alerts))
    total_incidents = stats.get("total_incidents", len(incidents))
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{total_incidents}</div>
            <div class="metric-label">Active Incidents</div>
            <div class="metric-delta up">▲ Requires attention</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        risk_color = severity_color('critical') if risk_score > 70 else severity_color('medium') if risk_score > 40 else severity_color('low')
        risk_delta_class = 'up' if risk_score > 50 else 'down'
        risk_delta_text = '▲ High Risk' if risk_score > 50 else '▼ Moderate'
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: {risk_color}">{risk_score}</div>
            <div class="metric-label">Risk Score (0-100)</div>
            <div class="metric-delta {risk_delta_class}">{risk_delta_text}</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{total_alerts}</div>
            <div class="metric-label">Total Alerts Today</div>
            <div class="metric-delta up">▲ Active monitoring</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        comp_color = severity_color('low') if compliance > 70 else severity_color('medium') if compliance > 40 else severity_color('high')
        comp_delta_class = 'down' if compliance > 70 else 'up'
        comp_delta_text = '▼ Compliant' if compliance > 70 else '▲ Needs improvement'
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: {comp_color}">{compliance}%</div>
            <div class="metric-label">Compliance Score</div>
            <div class="metric-delta {comp_delta_class}">{comp_delta_text}</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # ── Row 2: Risk Gauge + Live Threat Map side by side ────────────────
    gauge_col, threat_col = st.columns([1, 2])
    
    with gauge_col:
        st.markdown("#### 📊 Overall Risk Gauge")
        # Plotly gauge chart for the risk score
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": "Risk Level", "font": {"size": 16, "color": "#94A3B8"}},
            number={"font": {"size": 48, "color": "#F1F5F9"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#4B5563"},
                "bar": {"color": severity_color("critical") if risk_score > 70 else severity_color("medium") if risk_score > 40 else severity_color("low")},
                "bgcolor": "rgba(30,41,59,0.3)",
                "steps": [
                    {"range": [0, 30], "color": "rgba(16,185,129,0.15)"},
                    {"range": [30, 60], "color": "rgba(245,158,11,0.15)"},
                    {"range": [60, 80], "color": "rgba(239,68,68,0.15)"},
                    {"range": [80, 100], "color": "rgba(185,28,28,0.15)"},
                ],
                "threshold": {
                    "line": {"color": "#EF4444", "width": 3},
                    "thickness": 0.8,
                    "value": risk_score,
                },
            },
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=280,
            margin=dict(l=20, r=20, t=40, b=20),
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with threat_col:
        st.markdown("#### 🔴 Live Threat Map — Top Critical Incidents")
        
        # Show top 3 most severe incidents as threat cards
        if incidents:
            sorted_incidents = sorted(
                incidents,
                key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x.get("severity", ""), 0),
                reverse=True,
            )[:3]
            
            for inc in sorted_incidents:
                sev = inc.get("severity", "medium")
                badge = severity_badge_html(sev)
                story_first_line = inc.get("story", "").split("\n")[0]
                rule = inc.get("rule_name", "Unknown")
                
                st.markdown(f"""
                <div class="threat-card">
                    <div class="threat-title">{badge} &nbsp; {rule}</div>
                    <div class="threat-detail">{story_first_line}</div>
                    <div class="threat-detail" style="margin-top:4px; color:#64748B">
                        Linked Alerts: {len(inc.get('alert_ids', []))} | 
                        {format_timestamp(inc.get('created_at', ''))}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No incidents detected yet. Try simulating an attack!")


# =============================================================================
# TAB 2: NETWORK TIMELINE
# =============================================================================

def render_network_timeline(alerts):
    """
    Network tab with a Plotly line chart showing:
        - Green line: baseline traffic level
        - Red markers/spikes: anomaly detections
        - Vertical lines at attack simulation timestamps
    """
    st.markdown("#### 📡 Network Anomaly Detection Timeline")
    st.markdown("_Baseline traffic compared with detected anomalies over time_")
    
    # Filter network alerts
    net_alerts = [a for a in alerts if a.get("module") == "network"]
    
    if not net_alerts:
        st.info("No network alerts recorded yet. Simulate an attack to see data.")
        return
    
    # Build dataframe for Plotly
    timeline_data = []
    for a in net_alerts:
        details = a.get("details", {})
        ts = a.get("timestamp", "")
        baseline = details.get("baseline_count", 40)
        actual = details.get("conn_count", baseline)
        
        # Baseline point
        timeline_data.append({
            "Time": ts,
            "Count": baseline,
            "Type": "Normal Baseline",
            "Severity": a.get("severity", "low"),
        })
        # Actual traffic point
        timeline_data.append({
            "Time": ts,
            "Count": actual,
            "Type": "Detected Anomalies",
            "Severity": a.get("severity", "low"),
        })
    
    df = pd.DataFrame(timeline_data)
    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    df = df.dropna(subset=["Time"]).sort_values("Time")
    
    # Create Plotly figure
    fig = go.Figure()
    
    # Baseline line (green)
    baseline_df = df[df["Type"] == "Normal Baseline"]
    fig.add_trace(go.Scatter(
        x=baseline_df["Time"],
        y=baseline_df["Count"],
        mode="lines+markers",
        name="Normal Baseline",
        line=dict(color="#10B981", width=2, dash="dash"),
        marker=dict(size=6, color="#10B981"),
        fill="tozeroy",
        fillcolor="rgba(16,185,129,0.05)",
    ))
    
    # Anomaly spikes (red)
    anomaly_df = df[df["Type"] == "Detected Anomalies"]
    fig.add_trace(go.Scatter(
        x=anomaly_df["Time"],
        y=anomaly_df["Count"],
        mode="lines+markers",
        name="Detected Anomalies",
        line=dict(color="#EF4444", width=3),
        marker=dict(size=10, color="#EF4444", symbol="triangle-up"),
        fill="tonexty",
        fillcolor="rgba(239,68,68,0.08)",
    ))
    
    # Add vertical lines for high/critical severity events
    # NOTE: Plotly's add_vline() has a known bug with datetime x-values
    # (TypeError: unsupported operand type(s) for +: 'int' and 'datetime').
    # We use add_shape() with ISO string x-coordinates as a workaround.
    for _, row in anomaly_df.iterrows():
        if row.get("Severity") in ("high", "critical"):
            x_str = row["Time"].isoformat() if hasattr(row["Time"], "isoformat") else str(row["Time"])
            fig.add_shape(
                type="line",
                x0=x_str, x1=x_str,
                y0=0, y1=1,
                yref="paper",
                line=dict(color="rgba(239,68,68,0.4)", width=1, dash="dot"),
            )
            fig.add_annotation(
                x=x_str, y=1, yref="paper",
                text="⚠", showarrow=False,
                font=dict(size=14, color="#EF4444"),
            )
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(15,23,42,0.3)",
        font=dict(color="#94A3B8"),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=12),
        ),
        xaxis=dict(
            title="Time",
            gridcolor="rgba(71,85,105,0.3)",
            showgrid=True,
        ),
        yaxis=dict(
            title="Connection Count",
            gridcolor="rgba(71,85,105,0.3)",
            showgrid=True,
        ),
        height=450,
        margin=dict(l=40, r=20, t=30, b=40),
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Alert details table below
    st.markdown("##### 📋 Network Alert Details")
    net_df = pd.DataFrame(net_alerts)
    if not net_df.empty:
        display_cols = ["id", "severity", "timestamp", "asset"]
        available = [c for c in display_cols if c in net_df.columns]
        st.dataframe(
            net_df[available],
            use_container_width=True,
            hide_index=True,
        )


# =============================================================================
# TAB 3: PASSWORD COMPLIANCE
# =============================================================================

def render_password_compliance(alerts):
    """
    Password tab with:
        - Compliance gauge (Plotly)
        - Policy violations table
        - Severity breakdown pie chart
        - Last audited timestamp
    """
    st.markdown("#### 🔑 Password Policy Compliance Audit")
    
    pwd_alerts = [a for a in alerts if a.get("module") == "password"]
    compliance = compute_password_compliance(alerts)
    
    # ── Row: Gauge + Pie Chart ──────────────────────────────────────────
    gauge_col, pie_col = st.columns(2)
    
    with gauge_col:
        st.markdown("##### Compliance Score")
        # Gauge chart
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=compliance,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": "Password Compliance", "font": {"size": 14, "color": "#94A3B8"}},
            number={"suffix": "%", "font": {"size": 48, "color": "#F1F5F9"}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#10B981" if compliance > 70 else "#F59E0B" if compliance > 40 else "#EF4444"},
                "bgcolor": "rgba(30,41,59,0.3)",
                "steps": [
                    {"range": [0, 40], "color": "rgba(239,68,68,0.15)"},
                    {"range": [40, 70], "color": "rgba(245,158,11,0.15)"},
                    {"range": [70, 100], "color": "rgba(16,185,129,0.15)"},
                ],
            },
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            height=280,
            margin=dict(l=20, r=20, t=40, b=20),
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with pie_col:
        st.markdown("##### Severity Breakdown")
        if pwd_alerts:
            sev_counts = {}
            for a in pwd_alerts:
                s = a.get("severity", "info")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            
            fig = px.pie(
                names=list(sev_counts.keys()),
                values=list(sev_counts.values()),
                color=list(sev_counts.keys()),
                color_discrete_map=SEVERITY_COLORS,
                hole=0.4,
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94A3B8"),
                height=280,
                margin=dict(l=20, r=20, t=20, b=20),
                showlegend=True,
                legend=dict(font=dict(size=11)),
            )
            fig.update_traces(textposition='inside', textinfo='label+percent')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No password audit data available.")
    
    # ── Policy Violations Table ─────────────────────────────────────────
    st.markdown("##### 📋 Policy Violations")
    
    if pwd_alerts:
        violations = []
        for a in pwd_alerts:
            details = a.get("details", {})
            issues = details.get("issues", [])
            for issue in issues:
                violations.append({
                    "Alert ID": a.get("id"),
                    "Username": details.get("username", "N/A"),
                    "Policy": details.get("policy", "N/A"),
                    "Issue": issue,
                    "Severity": a.get("severity", "info"),
                    "Timestamp": format_timestamp(a.get("timestamp", "")),
                })
        
        if violations:
            viol_df = pd.DataFrame(violations)
            st.dataframe(viol_df, use_container_width=True, hide_index=True)
        else:
            st.info("No specific violations found in alert details.")
        
        # Last audited
        timestamps = [a.get("timestamp", "") for a in pwd_alerts]
        if timestamps:
            latest = max(timestamps)
            st.caption(f"🕐 Last Audited: {format_timestamp(latest)}")
    else:
        st.info("No password audit alerts recorded. Simulate an attack to see data.")


# =============================================================================
# TAB 4: API VULNERABILITIES
# =============================================================================

def render_api_vulnerabilities(alerts):
    """
    API tab with:
        - Filterable dataframe of vulnerabilities
        - OWASP category bar chart
    """
    st.markdown("#### 🌐 API Security Vulnerability Scanner")
    
    api_alerts = [a for a in alerts if a.get("module") == "api"]
    
    if not api_alerts:
        st.info("No API vulnerability alerts recorded. Simulate an attack to see data.")
        return
    
    # ── Severity Filter ─────────────────────────────────────────────────
    severity_filter = st.selectbox(
        "Filter by Severity",
        options=["All", "critical", "high", "medium", "low", "info"],
        index=0,
        key="api_severity_filter",
    )
    
    if severity_filter != "All":
        api_alerts = [a for a in api_alerts if a.get("severity") == severity_filter]
    
    # ── Build Vulnerability Table ───────────────────────────────────────
    vuln_data = []
    for a in api_alerts:
        details = a.get("details", {})
        vuln_data.append({
            "Endpoint": details.get("endpoint", "N/A"),
            "OWASP Category": details.get("owasp_category", "Unknown"),
            "Severity": a.get("severity", "info").upper(),
            "Method": details.get("method", "GET"),
            "Description": details.get("description", "No description"),
            "Discovered": format_timestamp(a.get("timestamp", "")),
        })
    
    vuln_df = pd.DataFrame(vuln_data)
    st.dataframe(vuln_df, use_container_width=True, hide_index=True)
    
    # ── OWASP Category Bar Chart ────────────────────────────────────────
    st.markdown("##### 📊 Vulnerabilities by OWASP Top 10 Category")
    
    if vuln_data:
        owasp_counts = {}
        for v in vuln_data:
            cat = v["OWASP Category"]
            owasp_counts[cat] = owasp_counts.get(cat, 0) + 1
        
        fig = px.bar(
            x=list(owasp_counts.keys()),
            y=list(owasp_counts.values()),
            labels={"x": "OWASP Category", "y": "Count"},
            color=list(owasp_counts.values()),
            color_continuous_scale=["#F59E0B", "#EF4444", "#B91C1C"],
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.3)",
            font=dict(color="#94A3B8"),
            height=350,
            margin=dict(l=40, r=20, t=20, b=80),
            xaxis=dict(tickangle=-30),
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# TAB 5: CORRELATED INCIDENTS — THE MOST IMPORTANT TAB
# =============================================================================

def render_correlated_incidents(alerts, incidents):
    """
    THE SHOWPIECE TAB — demonstrates the core value of SecuriSphere.
    
    Shows:
        - Before vs After Correlation toggle
        - Incident cards with severity badge, story, timeline, actions
    """
    st.markdown("#### 🔗 Correlated Security Incidents")
    st.markdown(
        "_This is the **core value** of SecuriSphere — turning scattered alerts "
        "into prioritized, actionable incidents with clear threat stories._"
    )
    
    # ── "Before vs After" Correlation Toggle ────────────────────────────
    st.markdown("##### ⚡ Before vs After Correlation")
    view_mode = st.toggle("Show 'Before Correlation' view", value=False, key="correlation_toggle")
    
    if view_mode:
        # BEFORE: Show raw alerts as flat list — no context, hard to prioritize
        before_col, after_col = st.columns(2)
        
        with before_col:
            st.markdown("""
            <div class="correlation-before">
                <div class="correlation-label">❌ Before Correlation</div>
                <p style="color:#CBD5E1; font-size:0.85rem;">
                    Raw alerts from 3 independent modules. No context, no priority,
                    no story. An analyst would have to manually review each alert
                    and figure out connections.
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            for a in alerts[:6]:
                badge = severity_badge_html(a.get("severity", "info"))
                st.markdown(f"""
                <div style="padding:8px 12px; margin:4px 0; background:rgba(30,41,59,0.5); 
                     border-radius:8px; border-left:3px solid {severity_color(a.get('severity','info'))};">
                    {badge} &nbsp; 
                    <span style="color:#CBD5E1; font-size:0.82rem">
                        [{a.get('module','?').upper()}] {a.get('type','')} — {a.get('asset','')}
                    </span>
                </div>
                """, unsafe_allow_html=True)
        
        with after_col:
            st.markdown("""
            <div class="correlation-after">
                <div class="correlation-label">✅ After Correlation</div>
                <p style="color:#CBD5E1; font-size:0.85rem;">
                    The correlation engine groups related alerts, escalates severity,
                    and generates a human-readable threat story. 
                    <strong>3 medium alerts → 1 critical incident.</strong>
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            for inc in incidents[:3]:
                badge = severity_badge_html(inc.get("severity", "high"), large=True)
                st.markdown(f"""
                <div style="padding:8px 12px; margin:4px 0; background:rgba(99,102,241,0.08); 
                     border-radius:8px; border-left:3px solid {severity_color(inc.get('severity','high'))};">
                    {badge} &nbsp;
                    <span style="color:#E2E8F0; font-size:0.85rem; font-weight:600">
                        {inc.get('rule_name','')}
                    </span>
                    <div style="color:#94A3B8; font-size:0.75rem; margin-top:4px">
                        Groups {len(inc.get('alert_ids',[]))} alerts → Escalated to {inc.get('severity','').upper()}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
    
    # ── Individual Incident Cards ───────────────────────────────────────
    st.markdown("##### 📋 Incident Details")
    
    if not incidents:
        st.info("🔎 No correlated incidents yet. Click **Simulate Attack** in the sidebar!")
        return
    
    for inc in incidents:
        sev = inc.get("severity", "medium")
        rule = inc.get("rule_name", "Unknown Incident")
        story = inc.get("story", "No details available.")
        alert_ids = inc.get("alert_ids", [])
        created = format_timestamp(inc.get("created_at", ""))
        badge = severity_badge_html(sev, large=True)
        
        # Determine affected asset from linked alerts
        linked_alerts_data = [get_alert_by_id(alerts, aid) for aid in alert_ids]
        linked_alerts_data = [a for a in linked_alerts_data if a is not None]
        affected_assets = list(set(a.get("asset", "Unknown") for a in linked_alerts_data))
        asset_str = ", ".join(affected_assets) if affected_assets else "victim-app:8000"
        
        with st.expander(f"{'🔴' if sev == 'critical' else '🟠' if sev == 'high' else '🟡'} {rule} — {sev.upper()}", expanded=(sev == "critical")):
            # Header with badge
            st.markdown(f"""
            <div class="incident-card {sev}">
                <div class="incident-title">{badge} &nbsp; {rule}</div>
                <div style="color:#64748B; font-size:0.8rem; margin-bottom:0.8rem">
                    Incident ID: {inc.get('incident_id', 'N/A')[:12]}... | 
                    Detected: {created} | 
                    Affected Asset: <strong>{asset_str}</strong>
                </div>
                <div class="incident-story">{story.replace(chr(10), '<br>')}</div>
            </div>
            """, unsafe_allow_html=True)
            
            # ── Timeline of Linked Alerts ───────────────────────────────
            if linked_alerts_data:
                st.markdown("**📅 Timeline of Linked Alerts:**")
                timeline_rows = []
                for la in linked_alerts_data:
                    timeline_rows.append({
                        "Module": la.get("module", "?").upper(),
                        "Time": format_timestamp(la.get("timestamp", "")),
                        "Original Severity": la.get("severity", "info").upper(),
                    })
                st.dataframe(
                    pd.DataFrame(timeline_rows),
                    use_container_width=True,
                    hide_index=True,
                )
            
            # ── Recommended Actions ─────────────────────────────────────
            st.markdown("**🛡️ Recommended Actions:**")
            # Extract actions from story text
            if "Recommended action:" in story:
                action_text = story.split("Recommended action:")[-1].strip()
                action_items = [item.strip() for item in action_text.split(",") if item.strip()]
                for item in action_items:
                    st.markdown(f"- {item}")
            else:
                st.markdown("- Investigate all linked alerts immediately")
                st.markdown("- Isolate the affected asset if confirmed")
                st.markdown("- Rotate credentials and review access logs")
                st.markdown("- Document findings for incident response report")


# =============================================================================
# TAB 6: RISK PRIORITIZATION
# =============================================================================

def render_risk_prioritization(alerts, incidents):
    """
    Risk tab with a prioritized table sorted by risk score.
    Columns: Asset, Risk Score, Threat Story, Number of Signals, Last Seen
    Heatmap-style background coloring based on severity.
    """
    st.markdown("#### ⚠️ Risk Prioritization Matrix")
    st.markdown("_Assets ranked by overall risk level — highest risk at top_")
    
    # ── Build per-asset risk data ───────────────────────────────────────
    # Group alerts by asset and compute per-asset risk
    asset_data = {}
    for a in alerts:
        asset = a.get("asset", "Unknown")
        if asset not in asset_data:
            asset_data[asset] = {
                "alerts": [],
                "incidents": [],
                "last_seen": "",
            }
        asset_data[asset]["alerts"].append(a)
        ts = a.get("timestamp", "")
        if ts > asset_data[asset]["last_seen"]:
            asset_data[asset]["last_seen"] = ts
    
    # Map incidents to assets
    for inc in incidents:
        alert_ids = inc.get("alert_ids", [])
        for a in alerts:
            if a.get("id") in alert_ids:
                asset = a.get("asset", "Unknown")
                if asset in asset_data:
                    if inc not in asset_data[asset]["incidents"]:
                        asset_data[asset]["incidents"].append(inc)
    
    # Build table rows
    risk_rows = []
    severity_weights = {"info": 1, "low": 3, "medium": 8, "high": 15, "critical": 25}
    
    for asset, data in asset_data.items():
        alert_score = sum(severity_weights.get(a.get("severity", "info"), 1) for a in data["alerts"])
        incident_bonus = len(data["incidents"]) * 15
        raw_risk = alert_score + incident_bonus
        risk_score = min(100, int((raw_risk / 150) * 100))
        
        # Get threat story from highest-severity incident
        if data["incidents"]:
            top_inc = max(
                data["incidents"],
                key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x.get("severity", ""), 0),
            )
            threat_story = top_inc.get("rule_name", "Multiple signals detected")
        else:
            threat_story = "Individual alerts — not yet correlated"
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        risk_rows.append({
            "Asset": asset,
            "Risk Score": risk_score,
            "Risk Level": risk_level,
            "Threat Story": threat_story,
            "Signals": len(data["alerts"]),
            "Incidents": len(data["incidents"]),
            "Last Seen": format_timestamp(data["last_seen"]),
        })
    
    # Sort by risk score descending
    risk_rows.sort(key=lambda x: x["Risk Score"], reverse=True)
    
    if risk_rows:
        risk_df = pd.DataFrame(risk_rows)
        
        # Apply color coding using Pandas Styler
        def color_risk(val):
            if val == "CRITICAL":
                return f"background-color: rgba(185,28,28,0.25); color: #FCA5A5; font-weight: 700"
            elif val == "HIGH":
                return f"background-color: rgba(239,68,68,0.15); color: #EF4444; font-weight: 600"
            elif val == "MEDIUM":
                return f"background-color: rgba(245,158,11,0.15); color: #F59E0B; font-weight: 600"
            else:
                return f"background-color: rgba(16,185,129,0.10); color: #10B981"
        
        def color_score(val):
            if val >= 80:
                return "color: #FCA5A5; font-weight: 800; font-size: 1.1em"
            elif val >= 60:
                return "color: #EF4444; font-weight: 700"
            elif val >= 30:
                return "color: #F59E0B; font-weight: 600"
            else:
                return "color: #10B981"
        
        styled = risk_df.style.map(
            color_risk, subset=["Risk Level"]
        ).map(
            color_score, subset=["Risk Score"]
        )
        
        st.dataframe(styled, use_container_width=True, hide_index=True, height=400)
    else:
        st.info("No risk data available. Simulate alerts to populate.")
    
    # ── Severity Distribution Heatmap ───────────────────────────────────
    if alerts:
        st.markdown("##### 🗺️ Alert Severity Distribution")
        sev_mod_data = []
        for a in alerts:
            sev_mod_data.append({
                "Module": a.get("module", "?").upper(),
                "Severity": a.get("severity", "info").upper()
            })
        sev_df = pd.DataFrame(sev_mod_data)
        cross = pd.crosstab(sev_df["Module"], sev_df["Severity"])
        
        fig = px.imshow(
            cross,
            color_continuous_scale=["#0F172A", "#F59E0B", "#EF4444", "#B91C1C"],
            labels=dict(x="Severity", y="Module", color="Count"),
            text_auto=True,
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#94A3B8"),
            height=250,
            margin=dict(l=60, r=20, t=20, b=40),
        )
        st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# MAIN APPLICATION ENTRY POINT
# =============================================================================

def main():
    """
    Main function that orchestrates the entire dashboard.
    
    Flow:
        1. Render sidebar (branding, controls, exports)
        2. Fetch data from backend (or use fallback)
        3. Render the 6 tabs
        4. Handle auto-refresh if enabled
    """
    # ── Title Bar ───────────────────────────────────────────────────────
    st.markdown('<h1 class="main-title">🛡️ SecuriSphere</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-title">Multi-Layer Integrated Cybersecurity Monitoring System</p>',
        unsafe_allow_html=True,
    )
    
    # ── Sidebar ─────────────────────────────────────────────────────────
    auto_refresh = render_sidebar()
    
    # ── Fetch Data ──────────────────────────────────────────────────────
    # These are cached with TTL=5 seconds (see utils.py)
    alerts = fetch_alerts()
    incidents = fetch_incidents()
    stats = fetch_stats()
    
    # Store in session state for export buttons in sidebar
    st.session_state.alerts_data = alerts
    st.session_state.incidents_data = incidents
    st.session_state.stats_data = stats
    
    # ── Tab Layout ──────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📊 Overview",
        "📡 Network Timeline",
        "🔑 Password Compliance",
        "🌐 API Vulnerabilities",
        "🔗 Correlated Incidents ⭐",
        "⚠️ Risk Prioritization",
    ])
    
    with tab1:
        render_overview(alerts, incidents, stats)
    
    with tab2:
        render_network_timeline(alerts)
    
    with tab3:
        render_password_compliance(alerts)
    
    with tab4:
        render_api_vulnerabilities(alerts)
    
    with tab5:
        render_correlated_incidents(alerts, incidents)
    
    with tab6:
        render_risk_prioritization(alerts, incidents)
    
    # ── Auto-Refresh Handler ────────────────────────────────────────────
    # When enabled, the dashboard will poll the backend every 8 seconds
    if auto_refresh:
        time.sleep(8)
        st.rerun()


# =============================================================================
# Run the app
# =============================================================================
# NOTE: When running via `streamlit run`, __name__ is NOT "__main__".
# We must call main() unconditionally so the dashboard renders.
main()
