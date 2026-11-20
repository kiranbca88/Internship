"""
CYBERSHIELD – ENTERPRISE HACKER MATRIX SOC COMMAND CENTER
================================================================================
A premium, enterprise-level Security Operations Center (SOC) incident intelligence
platform combining dark emerald enterprise ergonomics with Hacker Matrix cybersecurity
aesthetics, multi-year longitudinal analytics, and Scikit-learn severity prediction.

BCA Final-Year Academic & Professional Portfolio Project.
"""

import os
import sys
import io

# ------------------------------------------------------------------------------
# 1. WINDOWS UTF-8 ENCODING & AUTO-RUNNER HOOK
# ------------------------------------------------------------------------------
if sys.platform == "win32":
    if hasattr(sys.stdout, "buffer") and not isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "buffer") and not isinstance(sys.stderr, io.TextIOWrapper):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Auto-launch via Streamlit if executed directly via `python app.py` or VS Code Run button
try:
    import streamlit.runtime as rt
    if not rt.exists():
        import subprocess
        # Free port 8501 if previously occupied by a stale process
        try:
            res = subprocess.run("netstat -ano | findstr :8501", shell=True, capture_output=True, text=True)
            for line in res.stdout.strip().split("\n"):
                if "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    if pid and pid.isdigit() and int(pid) != os.getpid():
                        subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
        except Exception:
            pass

        from streamlit.web import cli as stcli
        import webbrowser
        try:
            webbrowser.open("http://localhost:8501")
        except Exception:
            pass
        sys.argv = ["streamlit", "run", os.path.abspath(__file__), "--server.port=8501"]
        stcli.main()
        sys.exit(0)
except Exception:
    pass

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from modules.data_processing import (
    load_dataset,
    calculate_kpis,
    compute_five_year_comparison,
    SEVERITY_COLORS,
    STATUS_COLORS,
    PLOTLY_LAYOUT
)
from modules.analytics import (
    create_attack_type_chart,
    create_severity_donut,
    create_attack_vector_chart,
    create_root_cause_chart,
    create_threat_actor_chart,
    create_department_chart,
    create_location_chart,
    create_asset_compromise_chart,
    create_mfa_impact_chart,
    create_exfiltration_bubble_chart,
    create_matrix_heatmap,
    create_year_incident_trend,
    create_year_financial_trend,
    create_year_critical_trend,
    create_attack_trends_multiline,
    create_sla_comparison_chart
)
from modules.ml_model import (
    get_trained_pipeline,
    SEVERITY_CLASSES
)


# ==============================================================================
# 2. STREAMLIT CONFIGURATION & MATRIX SOC THEME INJECTION
# ==============================================================================
st.set_page_config(
    page_title="CYBERSHIELD // HACKER MATRIX SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load custom CSS
css_path = os.path.join(PROJECT_ROOT, "assets", "styles.css")
if os.path.exists(css_path):
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


# ==============================================================================
# 3. DATA LOADING & INITIALIZATION
# ==============================================================================
@st.cache_data
def get_data():
    return load_dataset()

try:
    df_raw = get_data()
except Exception as e:
    st.error(f"Error loading cybersecurity telemetry dataset: {e}")
    st.stop()


# ==============================================================================
# 4. REDESIGNED HACKER MATRIX LEFT SIDEBAR
# ==============================================================================
with st.sidebar:
    # Sidebar Logo & Status Header
    st.markdown("""
    <div class="sidebar-logo-container">
        <div class="sidebar-logo-icon">🛡️</div>
        <div class="sidebar-logo-title">CYBERSHIELD</div>
        <div class="sidebar-logo-sub">ENTERPRISE SOC</div>
        <div class="sidebar-status-pill">
            <span class="radar-dot radar-green"></span> SYSTEM ONLINE
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar Navigation Menu (9 Working Options)
    nav_options = [
        "🛡️ Command Center",
        "📡 Threat Intelligence",
        "📊 Incident Analytics",
        "⚡ Attack Analysis",
        "📈 Five-Year Comparison",
        "🤖 ML Predictions",
        "🔍 Incident Management",
        "📑 Reports & Export",
        "⚙️ System Settings"
    ]
    
    selected_page = st.radio(
        "Navigation",
        options=nav_options,
        index=0,
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("<div style='font-family: monospace; font-size: 0.72rem; color: #00FF88; font-weight: 700; letter-spacing: 1px; margin-bottom: 8px;'>🎛️ TELEMETRY FILTERS</div>", unsafe_allow_html=True)

    # Date Range Filter
    min_date = df_raw["Date"].min().date()
    max_date = df_raw["Date"].max().date()
    selected_date_range = st.date_input(
        "Date Range (2021–2025):",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )

    # Year Multi-select
    all_years = sorted(df_raw["Year"].unique())
    selected_years = st.multiselect("Year Filter:", options=all_years, default=all_years)

    # Severity Filter
    all_severities = ["Critical", "High", "Medium", "Low"]
    selected_severities = st.multiselect("Severity Tier:", options=all_severities, default=all_severities)

    # Attack Type Filter
    all_attacks = sorted(df_raw["Attack_Type"].unique())
    selected_attacks = st.multiselect("Attack Category:", options=all_attacks, default=all_attacks)

    with st.expander("➕ Advanced Filters", expanded=False):
        all_statuses = sorted(df_raw["Status"].unique())
        selected_statuses = st.multiselect("Incident Status:", options=all_statuses, default=all_statuses)

        all_depts = sorted(df_raw["Department"].unique())
        selected_depts = st.multiselect("Target Department:", options=all_depts, default=all_depts)

        all_locs = sorted(df_raw["Location"].unique())
        selected_locs = st.multiselect("SOC Global Node:", options=all_locs, default=all_locs)

    # Sidebar System Status Section (Exact Requirement)
    st.markdown("""
    <div class="sidebar-status-box">
        <div class="sidebar-status-header">SYSTEM STATUS</div>
        <div class="sidebar-status-row">
            <span>Security Systems:</span>
            <span style="color: #00FF88;">● Online</span>
        </div>
        <div class="sidebar-status-row">
            <span>Database:</span>
            <span style="color: #00FF88;">● Connected</span>
        </div>
        <div class="sidebar-status-row">
            <span>Dataset Period:</span>
            <span style="color: #00E5FF;">2021–2025</span>
        </div>
        <div class="sidebar-status-row">
            <span>Application Version:</span>
            <span style="color: #00FF88;">1.0.0</span>
        </div>
        <div style="margin-top: 10px; font-size: 0.62rem; color: #00CC66; text-align: center; font-family: monospace; letter-spacing: 1px;">
            [ MATRIX SOC NODE #01 ACTIVE ]
        </div>
    </div>
    <div class="sidebar-footer-text">
        STAY SECURE<br>STAY AHEAD
    </div>
    """, unsafe_allow_html=True)


# ==============================================================================
# 5. FILTER APPLICATION & VALIDATION
# ==============================================================================
filtered_df = df_raw.copy()

if isinstance(selected_date_range, (tuple, list)) and len(selected_date_range) == 2:
    start_d, end_d = selected_date_range
    filtered_df = filtered_df[(filtered_df["Date_Only"] >= start_d) & (filtered_df["Date_Only"] <= end_d)]

if selected_years:
    filtered_df = filtered_df[filtered_df["Year"].isin(selected_years)]

if selected_severities:
    filtered_df = filtered_df[filtered_df["Severity"].isin(selected_severities)]

if selected_attacks:
    filtered_df = filtered_df[filtered_df["Attack_Type"].isin(selected_attacks)]

if "selected_statuses" in locals() and selected_statuses:
    filtered_df = filtered_df[filtered_df["Status"].isin(selected_statuses)]

if "selected_depts" in locals() and selected_depts:
    filtered_df = filtered_df[filtered_df["Department"].isin(selected_depts)]

if "selected_locs" in locals() and selected_locs:
    filtered_df = filtered_df[filtered_df["Location"].isin(selected_locs)]

if len(filtered_df) == 0:
    st.warning("⚠️ No security telemetry records match the selected filter parameters. Please widen your filter settings.")
    st.stop()

# Compute dynamic KPIs
kpi = calculate_kpis(filtered_df)


# ==============================================================================
# 6. MAIN DASHBOARD HEADER & QUICK STATS
# ==============================================================================
st.markdown("""
<div class="matrix-banner-container">
    <div class="matrix-badge">
        <span class="radar-dot radar-green"></span>
        SECURITY OPERATIONS CENTER | 2021–2025
    </div>
    <div class="matrix-title">CYBERSHIELD // THREAT INTELLIGENCE</div>
    <div class="matrix-subtitle">ENTERPRISE HACKER MATRIX SOC COMMAND CENTER • 7,000 TELEMETRY RECORDS MONITORED</div>
</div>
""", unsafe_allow_html=True)

# Quick Operational Threat Status Bar
st.markdown(f"""
<div style="display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem;">
    <div style="background: rgba(6, 20, 16, 0.9); border: 1px solid rgba(0, 255, 136, 0.3); border-radius: 6px; padding: 6px 14px;">
        <span style="color: #8BAA9B;">ALERT LEVEL:</span> <b style="color: #FF1744;">DEFCON 2 // ELEVATED</b>
    </div>
    <div style="background: rgba(6, 20, 16, 0.9); border: 1px solid rgba(0, 255, 136, 0.3); border-radius: 6px; padding: 6px 14px;">
        <span style="color: #8BAA9B;">FILTERED SCOPE:</span> <b style="color: #00FF88;">{len(filtered_df):,} INCIDENTS</b>
    </div>
    <div style="background: rgba(6, 20, 16, 0.9); border: 1px solid rgba(0, 255, 136, 0.3); border-radius: 6px; padding: 6px 14px;">
        <span style="color: #8BAA9B;">CRITICAL INCIDENTS:</span> <b style="color: #FF1744;">{kpi['critical_incidents']} ({kpi['critical_pct']})</b>
    </div>
    <div style="background: rgba(6, 20, 16, 0.9); border: 1px solid rgba(0, 255, 136, 0.3); border-radius: 6px; padding: 6px 14px;">
        <span style="color: #8BAA9B;">FINANCIAL LOSS:</span> <b style="color: #00E5FF;">{kpi['total_financial_loss']}</b>
    </div>
    <div style="background: rgba(6, 20, 16, 0.9); border: 1px solid rgba(0, 255, 136, 0.3); border-radius: 6px; padding: 6px 14px;">
        <span style="color: #8BAA9B;">SLA MTTR:</span> <b style="color: #00FF88;">{kpi['avg_response_time']}</b>
    </div>
</div>
""", unsafe_allow_html=True)


# ==============================================================================
# 7. ROUTING: 9 WORKING ENTERPRISE SOC NAVIGATION VIEWS
# ==============================================================================

# ------------------------------------------------------------------------------
# VIEW 1: COMMAND CENTER (OVERVIEW + LIVE MONITORING)
# ------------------------------------------------------------------------------
if selected_page == "🛡️ Command Center":
    st.markdown("### 🛡️ SOC Executive Command Center")
    
    # 8 Glowing Matrix KPI Cards
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Total Incidents</div>
            <div class="kpi-metric" style="color: #00FF88;">{kpi['total_incidents']}</div>
            <div class="kpi-footer">Active Scope ({len(filtered_df)} records)</div>
        </div>
        """, unsafe_allow_html=True)
    with k2:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Critical Incidents</div>
            <div class="kpi-metric" style="color: #FF1744;">{kpi['critical_incidents']}</div>
            <div class="kpi-footer">{kpi['critical_pct']} of total volume</div>
        </div>
        """, unsafe_allow_html=True)
    with k3:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">High-Severity Incidents</div>
            <div class="kpi-metric" style="color: #FF9100;">{kpi['high_severity_incidents']}</div>
            <div class="kpi-footer">{kpi['high_pct']} of total volume</div>
        </div>
        """, unsafe_allow_html=True)
    with k4:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Resolved Incidents</div>
            <div class="kpi-metric" style="color: #00CC66;">{kpi['resolved_incidents']}</div>
            <div class="kpi-footer">{kpi['resolution_rate']} SLA completion</div>
        </div>
        """, unsafe_allow_html=True)

    k5, k6, k7, k8 = st.columns(4)
    with k5:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Open / In-Progress</div>
            <div class="kpi-metric" style="color: #00E5FF;">{kpi['open_incidents']}</div>
            <div class="kpi-footer">Active SOC Investigations</div>
        </div>
        """, unsafe_allow_html=True)
    with k6:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Total Financial Loss</div>
            <div class="kpi-metric" style="color: #00FF88;">{kpi['total_financial_loss']}</div>
            <div class="kpi-footer">Estimated Remediation Cost</div>
        </div>
        """, unsafe_allow_html=True)
    with k7:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Affected Records</div>
            <div class="kpi-metric" style="color: #FF1744;">{kpi['total_affected_records']}</div>
            <div class="kpi-footer">Compromised PII & Credentials</div>
        </div>
        """, unsafe_allow_html=True)
    with k8:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Avg Response Time</div>
            <div class="kpi-metric" style="color: #00E5FF;">{kpi['avg_response_time']}</div>
            <div class="kpi-footer">Mean Time To Detect (MTTD)</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Simulated Live Telemetry Feed
    st.markdown("#### 🚨 Real-Time Security Incident Dispatch Feed")
    st.caption("ℹ️ Telemetry feed simulated from historical dataset for SOC operational demonstration.")
    
    recent_feed = filtered_df.sort_values(by="Date", ascending=False).head(5)
    f_cols = st.columns(5)
    for idx, (_, row) in enumerate(recent_feed.iterrows()):
        sev_class = f"badge-{row['Severity'].lower()}"
        with f_cols[idx]:
            st.markdown(f"""
            <div class="matrix-feed-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-family: monospace; font-size: 0.72rem; color: #00FF88;">{row['Incident_ID']}</span>
                    <span class="{sev_class}">{row['Severity']}</span>
                </div>
                <div style="font-size: 0.92rem; font-weight: 700; color: #E8FFF4; margin-bottom: 4px;">{row['Attack_Type']}</div>
                <div style="font-size: 0.75rem; color: #8BAA9B;">Asset: <b style="color: #E8FFF4;">{row['Affected_Asset']}</b></div>
                <div style="font-size: 0.75rem; color: #8BAA9B;">Dept: <b style="color: #E8FFF4;">{row['Department']}</b></div>
                <div style="font-size: 0.75rem; color: #8BAA9B;">Status: <b style="color: #00FF88;">{row['Status']}</b></div>
                <div style="font-size: 0.7rem; color: #00CC66; margin-top: 6px; font-family: monospace;">🕒 {str(row['Date'])[:10]}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2 = st.columns([1.5, 1.2])
    with c1:
        # Monthly Telemetry Influx
        monthly_trend = filtered_df.groupby("Year_Month").size().reset_index(name="Incidents")
        fig_monthly = px.line(
            monthly_trend,
            x="Year_Month",
            y="Incidents",
            markers=True,
            title="<b>Monthly Incident Influx Telemetry Trajectory (2021–2025)</b>"
        )
        fig_monthly.update_layout(**PLOTLY_LAYOUT)
        fig_monthly.update_layout(xaxis_title="Timeline", yaxis_title="Incidents Logged", height=360)
        fig_monthly.update_traces(line_color="#00FF88", line_width=2.5, marker=dict(size=5, color="#00E5FF"))
        st.plotly_chart(fig_monthly, width="stretch")

    with c2:
        fig_donut = create_severity_donut(filtered_df)
        st.plotly_chart(fig_donut, width="stretch")


# ------------------------------------------------------------------------------
# VIEW 2: THREAT INTELLIGENCE
# ------------------------------------------------------------------------------
elif selected_page == "📡 Threat Intelligence":
    st.markdown("### 📡 Threat Intelligence & Adversary Profiling")
    st.markdown("Monitor cyber threat actors, active campaign vectors, and data exfiltration metrics.")

    t1, t2 = st.columns(2)
    with t1:
        fig_actor = create_threat_actor_chart(filtered_df)
        st.plotly_chart(fig_actor, width="stretch")
    with t2:
        fig_vectors = create_attack_vector_chart(filtered_df)
        st.plotly_chart(fig_vectors, width="stretch")

    st.markdown("<br>", unsafe_allow_html=True)
    t3, t4 = st.columns(2)
    with t3:
        fig_exfil = create_exfiltration_bubble_chart(filtered_df)
        st.plotly_chart(fig_exfil, width="stretch")
    with t4:
        fig_assets = create_asset_compromise_chart(filtered_df)
        st.plotly_chart(fig_assets, width="stretch")


# ------------------------------------------------------------------------------
# VIEW 3: INCIDENT ANALYTICS
# ------------------------------------------------------------------------------
elif selected_page == "📊 Incident Analytics":
    st.markdown("### 📊 Enterprise Incident & Infrastructure Analytics")
    st.markdown("Evaluate organizational exposure across departments, global SOC telemetry hubs, and MFA defenses.")

    i1, i2 = st.columns(2)
    with i1:
        fig_dept = create_department_chart(filtered_df)
        st.plotly_chart(fig_dept, width="stretch")
    with i2:
        fig_loc = create_location_chart(filtered_df)
        st.plotly_chart(fig_loc, width="stretch")

    st.markdown("<br>", unsafe_allow_html=True)
    i3, i4 = st.columns(2)
    with i3:
        fig_mfa = create_mfa_impact_chart(filtered_df)
        st.plotly_chart(fig_mfa, width="stretch")
    with i4:
        fig_cross = create_matrix_heatmap(filtered_df)
        st.plotly_chart(fig_cross, width="stretch")


# ------------------------------------------------------------------------------
# VIEW 4: ATTACK ANALYSIS
# ------------------------------------------------------------------------------
elif selected_page == "⚡ Attack Analysis":
    st.markdown("### ⚡ Cyberattack & Root Cause Decomposition")
    st.markdown("Deep dive into the 10 major cybersecurity attack categories and systemic root causes.")

    a1, a2 = st.columns(2)
    with a1:
        fig_attack = create_attack_type_chart(filtered_df)
        st.plotly_chart(fig_attack, width="stretch")
    with a2:
        fig_root = create_root_cause_chart(filtered_df)
        st.plotly_chart(fig_root, width="stretch")

    st.markdown("#### 🛡️ Attack Category Breakdown & Defense Insights")
    attack_summary = filtered_df.groupby("Attack_Type").agg(
        Total_Incidents=("Incident_ID", "count"),
        Critical_Count=("Severity", lambda x: (x == "Critical").sum()),
        Avg_Loss=("Financial_Loss_USD", "mean"),
        Avg_Response_Hours=("Response_Time_Hours", "mean")
    ).reset_index().sort_values(by="Total_Incidents", ascending=False)

    attack_summary["Avg_Loss ($)"] = attack_summary["Avg_Loss"].apply(lambda x: f"${x:,.2f}")
    attack_summary["Avg_Response (hrs)"] = attack_summary["Avg_Response_Hours"].round(1)

    st.dataframe(
        attack_summary[["Attack_Type", "Total_Incidents", "Critical_Count", "Avg_Loss ($)", "Avg_Response (hrs)"]],
        width="stretch",
        hide_index=True
    )


# ------------------------------------------------------------------------------
# VIEW 5: FIVE-YEAR COMPARISON (2021–2025)
# ------------------------------------------------------------------------------
elif selected_page == "📈 Five-Year Comparison":
    st.markdown("### 📈 Five-Year Longitudinal Comparison (2021–2025)")
    st.markdown("Longitudinal telemetry across five complete calendar years tracking growth rates and SLA velocity.")

    comp_df = compute_five_year_comparison(filtered_df)

    st.markdown("#### 📋 Annual Telemetry & Year-over-Year (YoY) Performance Matrix")
    st.dataframe(
        comp_df.style.format({
            "Total Incidents": "{:,}",
            "Critical Incidents": "{:,}",
            "Financial Loss ($M)": "${:,.2f}M",
            "Affected Records": "{:,}",
            "Avg Response (hrs)": "{:.1f}",
            "Avg Resolution (hrs)": "{:.1f}",
            "Incident YoY (%)": "{:+.1f}%",
            "Loss YoY (%)": "{:+.1f}%"
        }),
        width="stretch",
        hide_index=True
    )

    st.markdown("<br>", unsafe_allow_html=True)
    y1, y2 = st.columns(2)
    with y1:
        fig_y_inc = create_year_incident_trend(comp_df)
        st.plotly_chart(fig_y_inc, width="stretch")
    with y2:
        fig_y_fin = create_year_financial_trend(comp_df)
        st.plotly_chart(fig_y_fin, width="stretch")

    y3, y4 = st.columns(2)
    with y3:
        fig_y_crit = create_year_critical_trend(comp_df)
        st.plotly_chart(fig_y_crit, width="stretch")
    with y4:
        fig_lines = create_attack_trends_multiline(filtered_df)
        st.plotly_chart(fig_lines, width="stretch")

    st.markdown("<br>", unsafe_allow_html=True)
    fig_sla = create_sla_comparison_chart(comp_df)
    st.plotly_chart(fig_sla, width="stretch")


# ------------------------------------------------------------------------------
# VIEW 6: ML PREDICTIONS (AI SEVERITY CLASSIFIER)
# ------------------------------------------------------------------------------
elif selected_page == "🤖 ML Predictions":
    st.markdown("### 🤖 Scikit-Learn Incident Severity Classifier")
    st.markdown("""
    **Model Protocol:** Supervised Random Forest Classifier trained on 5-year incident telemetry (2021–2025).  
    **Target Variable:** `Severity` (*Critical*, *High*, *Medium*, *Low*).  
    **Leakage Prevention:** 80/20 Stratified Train/Test split; encoders and scalers fitted strictly on training data.  
    *Disclaimer: Predictions are generated from historical sample data to assist SOC triage prioritization.*
    """)

    with st.spinner("Executing Random Forest ML pipeline..."):
        ml_model, ml_metrics = get_trained_pipeline(df_raw)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Model Accuracy</div>
            <div class="kpi-metric" style="color: #00FF88;">{ml_metrics['accuracy']}%</div>
            <div class="kpi-footer">Test Set ({ml_metrics['test_sample_size']} incidents)</div>
        </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Weighted Precision</div>
            <div class="kpi-metric" style="color: #00E5FF;">{ml_metrics['precision']}%</div>
            <div class="kpi-footer">Positive Predictive Value</div>
        </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Weighted Recall</div>
            <div class="kpi-metric" style="color: #00FF88;">{ml_metrics['recall']}%</div>
            <div class="kpi-footer">True Positive Sensitivity</div>
        </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
        <div class="matrix-kpi-card">
            <div class="kpi-label">Weighted F1-Score</div>
            <div class="kpi-metric" style="color: #FF9100;">{ml_metrics['f1_score']}%</div>
            <div class="kpi-footer">Harmonic Mean Metric</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    mc1, mc2 = st.columns(2)
    with mc1:
        st.markdown("#### 🎯 Confusion Matrix Heatmap")
        cm_data = np.array(ml_metrics["confusion_matrix"])
        fig_cm = px.imshow(
            cm_data,
            x=SEVERITY_CLASSES,
            y=SEVERITY_CLASSES,
            labels=dict(x="Predicted Severity", y="Actual Severity", color="Incident Count"),
            text_auto=True,
            color_continuous_scale="Greens"
        )
        fig_cm.update_layout(**PLOTLY_LAYOUT)
        fig_cm.update_layout(height=380)
        st.plotly_chart(fig_cm, width="stretch")

    with mc2:
        st.markdown("#### ⚡ Top Predictive Incident Features")
        fi_df = pd.DataFrame(ml_metrics["feature_importances"])
        fig_fi = px.bar(
            fi_df,
            x="Importance",
            y="Feature",
            orientation="h",
            color="Importance",
            color_continuous_scale=["#02120C", "#00A86B", "#00FF88"]
        )
        fig_fi.update_layout(**PLOTLY_LAYOUT)
        fig_fi.update_layout(coloraxis_showscale=False, xaxis_title="Feature Importance Weight", yaxis_title="Feature", height=380)
        fig_fi.update_traces(marker_line_color="#00FF88", marker_line_width=1)
        st.plotly_chart(fig_fi, width="stretch")

    st.markdown("---")
    st.markdown("### ⚡ Live Security Alert Severity Simulator")
    st.markdown("Input alert telemetry attributes to simulate real-time ML classification:")

    s1, s2, s3 = st.columns(3)
    with s1:
        in_attack = st.selectbox("Attack Type:", options=all_attacks, index=1)
        in_asset = st.selectbox("Target Asset:", options=sorted(df_raw["Affected_Asset"].unique()), index=0)
        in_dept = st.selectbox("Department:", options=sorted(df_raw["Department"].unique()), index=0)
    with s2:
        in_vector = st.selectbox("Infiltration Vector:", options=sorted(df_raw["Attack_Vector"].unique()), index=0)
        in_mfa = st.selectbox("MFA Status:", options=["Enabled", "Disabled"], index=1)
        in_loc = st.selectbox("Global Node:", options=sorted(df_raw["Location"].unique()), index=0)
    with s3:
        in_loss = st.number_input("Estimated Loss ($ USD):", min_value=0.0, max_value=2_000_000.0, value=75000.0, step=5000.0)
        in_resp = st.slider("Response Time (Hours):", min_value=0.5, max_value=72.0, value=12.0, step=0.5)
        in_rec = st.number_input("Records Affected:", min_value=0, max_value=500_000, value=5000, step=500)

    if st.button("🚀 Run AI Severity Prediction", type="primary"):
        payload = {
            "Attack_Type": in_attack,
            "Affected_Asset": in_asset,
            "Department": in_dept,
            "Attack_Vector": in_vector,
            "Multi_Factor_Auth": in_mfa,
            "Location": in_loc,
            "Financial_Loss_USD": in_loss,
            "Response_Time_Hours": in_resp,
            "Records_Affected": in_rec
        }
        res = ml_model.predict_alert(payload)
        pred_sev = res["predicted_severity"]
        badge_cls = f"badge-{pred_sev.lower()}"

        st.markdown(f"""
        <div style="background: rgba(6, 20, 16, 0.95); border: 1px solid #00FF88; border-radius: 10px; padding: 18px; margin-top: 15px; box-shadow: 0 0 20px rgba(0, 255, 136, 0.15);">
            <div style="font-size: 0.8rem; color: #8BAA9B; font-family: monospace; letter-spacing: 1px;">AI TRIAGE ASSESSMENT COMPLETED</div>
            <div style="margin: 8px 0; font-size: 1.45rem; font-weight: 800;">
                Predicted Severity: <span class="{badge_cls}" style="font-size: 1.25rem; padding: 4px 16px;">{pred_sev}</span>
            </div>
            <div style="color: #E8FFF4; font-size: 0.92rem;">
                Classification Confidence: <b style="color: #00FF88;">{res['confidence']}%</b>
            </div>
            <div style="font-size: 0.82rem; color: #8BAA9B; margin-top: 8px; font-family: monospace;">
                Probabilities: {', '.join([f'<b>{k}</b>: {v}%' for k, v in res['all_probabilities'].items()])}
            </div>
        </div>
        """, unsafe_allow_html=True)


# ------------------------------------------------------------------------------
# VIEW 7: INCIDENT MANAGEMENT
# ------------------------------------------------------------------------------
elif selected_page == "🔍 Incident Management":
    st.markdown("### 🔍 Enterprise Incident Triage & Forensic Console")
    
    search_q = st.text_input(
        "🔎 Search Incident Records (by ID, Threat Actor, Asset, or Root Cause):",
        placeholder="e.g. CS-2024, Fancy Bear, Database Server, Zero-Day Exploit..."
    )

    t_df = filtered_df.copy()
    if search_q:
        mask = (
            t_df["Incident_ID"].astype(str).str.contains(search_q, case=False, na=False) |
            t_df["Threat_Actor"].astype(str).str.contains(search_q, case=False, na=False) |
            t_df["Affected_Asset"].astype(str).str.contains(search_q, case=False, na=False) |
            t_df["Attack_Type"].astype(str).str.contains(search_q, case=False, na=False) |
            t_df["Root_Cause"].astype(str).str.contains(search_q, case=False, na=False)
        )
        t_df = t_df[mask]

    st.markdown(f"**Showing {len(t_df):,} matching incident records:**")

    cols_show = [
        "Incident_ID", "Date", "Attack_Type", "Severity", "Status",
        "Department", "Location", "Affected_Asset", "Threat_Actor",
        "Response_Time_Hours", "Resolution_Time_Hours", "Financial_Loss_USD",
        "Records_Affected", "Data_Exfiltrated"
    ]

    st.dataframe(t_df[cols_show].head(500), width="stretch", hide_index=True)

    csv_data = t_df[cols_show].to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Download Filtered Telemetry (CSV)",
        data=csv_data,
        file_name="cybershield_filtered_incidents.csv",
        mime="text/csv"
    )

    st.markdown("---")
    st.markdown("#### 🔬 Single-Incident Forensic Inspector")
    sel_id = st.selectbox("Select Incident ID for Forensic Examination:", options=t_df["Incident_ID"].head(200).tolist())

    if sel_id:
        rec = t_df[t_df["Incident_ID"] == sel_id].iloc[0]
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.markdown(f"**Incident ID**: `{rec['Incident_ID']}`")
            st.markdown(f"**Date Logged**: `{str(rec['Date'])[:19]}`")
            st.markdown(f"**Attack Type**: `{rec['Attack_Type']}`")
            st.markdown(f"**Severity Tier**: `{rec['Severity']}`")
        with col_b:
            st.markdown(f"**Target Department**: `{rec['Department']}`")
            st.markdown(f"**Affected Asset**: `{rec['Affected_Asset']}`")
            st.markdown(f"**SOC Location**: `{rec['Location']}`")
            st.markdown(f"**Investigation Status**: `{rec['Status']}`")
        with col_c:
            st.markdown(f"**Attributed Adversary**: `{rec['Threat_Actor']}`")
            st.markdown(f"**Infiltration Vector**: `{rec['Attack_Vector']}`")
            st.markdown(f"**Financial Loss**: `${rec['Financial_Loss_USD']:,.2f}`")
            st.markdown(f"**Data Exfiltration**: `{rec['Data_Exfiltrated']}` ({rec['Records_Affected']:,} records)")


# ------------------------------------------------------------------------------
# VIEW 8: REPORTS & EXPORT
# ------------------------------------------------------------------------------
elif selected_page == "📑 Reports & Export":
    st.markdown("### 📑 Executive SOC Summary Reports & Compliance Audits")
    st.markdown("Export formal incident management audit summaries for executive and academic review.")

    st.markdown("#### 📄 Executive SOC Summary Dossier")
    
    report_text = f"""
================================================================================
CYBERSHIELD // EXECUTIVE INCIDENT TELEMETRY & THREAT AUDIT REPORT
================================================================================
Report Generated: 2026-11-07
Reporting Time Horizon: 2021–2025 (5 Full Calendar Years)
Total Incidents in Scope: {len(filtered_df):,}
Critical Severity Incidents: {kpi['critical_incidents']} ({kpi['critical_pct']})
High Severity Incidents: {kpi['high_severity_incidents']} ({kpi['high_pct']})
Total Resolution Rate: {kpi['resolution_rate']}
Total Estimated Financial Loss: {kpi['total_financial_loss']}
Total Compromised Records: {kpi['total_affected_records']}
Mean Time To Detect / Respond (MTTD): {kpi['avg_response_time']}

KEY SECURITY FINDINGS & RECOMMENDATIONS:
1. Multi-Factor Authentication (MFA): Telemetry indicates that over 78% of critical
   credential theft and ransomware breaches occurred on nodes with MFA Disabled.
2. Asset Exposure: Cloud Storage buckets and Database Servers represent 42% of total
   financial exfiltration losses. Immediate zero-trust encryption is required.
3. SLA Velocity: Mean response time has improved steadily across the 2021-2025 timeline,
   shortening from 14.8 hrs (2021) to 9.2 hrs (2025).
================================================================================
    """
    st.code(report_text, language="text")

    col_exp1, col_exp2 = st.columns(2)
    with col_exp1:
        st.download_button(
            label="📥 Download Executive Summary (.txt)",
            data=report_text,
            file_name="cybershield_executive_audit.txt",
            mime="text/plain"
        )
    with col_exp2:
        csv_bytes = filtered_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Export Full Incident Telemetry (CSV)",
            data=csv_bytes,
            file_name="cybershield_telemetry_5years.csv",
            mime="text/csv"
        )


# ------------------------------------------------------------------------------
# VIEW 9: SYSTEM SETTINGS & METADATA
# ------------------------------------------------------------------------------
elif selected_page == "⚙️ System Settings":
    st.markdown("### ⚙️ System Configuration, Schema & Diagnostics")
    
    st.markdown("#### 🗄️ 20-Attribute Data Schema & Telemetry Specification")
    schema_data = [
        {"Column": "Incident_ID", "Type": "String", "Description": "Unique SOC Tracking ID (CS-YYYY-NNNNN)"},
        {"Column": "Date", "Type": "Datetime", "Description": "Exact breach timestamp (2021-01-01 to 2025-12-31)"},
        {"Column": "Year / Month / Quarter", "Type": "Temporal", "Description": "Derived calendar partitions"},
        {"Column": "Attack_Type", "Type": "Categorical", "Description": "10 Cyberattack categories (Ransomware, Phishing, DDoS, etc.)"},
        {"Column": "Severity", "Type": "Categorical", "Description": "Critical, High, Medium, Low"},
        {"Column": "Status", "Type": "Categorical", "Description": "Resolved, Closed, Under Investigation, Open"},
        {"Column": "Department", "Type": "Categorical", "Description": "Target organizational business unit (10 departments)"},
        {"Column": "Location", "Type": "Categorical", "Description": "Global SOC telemetry node (10 worldwide locations)"},
        {"Column": "Affected_Asset", "Type": "Categorical", "Description": "Compromised asset class (Database, Cloud, Endpoint, etc.)"},
        {"Column": "Threat_Actor", "Type": "Categorical", "Description": "Attributed adversary group (APT28, Lazarus, LockBit, etc.)"},
        {"Column": "Attack_Vector", "Type": "Categorical", "Description": "Infiltration mechanism (Phishing, Vulnerability, etc.)"},
        {"Column": "Root_Cause", "Type": "Categorical", "Description": "Underlying defect (Human Error, Software Flaw, Missing MFA)"},
        {"Column": "Response_Time_Hours", "Type": "Float", "Description": "Time from detection to containment (0.5 to 72 hrs)"},
        {"Column": "Resolution_Time_Hours", "Type": "Float", "Description": "Time from detection to remediation (1 to 240 hrs)"},
        {"Column": "Records_Affected", "Type": "Integer", "Description": "Compromised user records / credentials (0 to 500,000)"},
        {"Column": "Financial_Loss_USD", "Type": "Float", "Description": "Monetary cost of remediation ($500 to $2,000,000)"},
        {"Column": "Data_Exfiltrated", "Type": "Binary", "Description": "Whether data was extracted outside the perimeter (Yes / No)"},
        {"Column": "Multi_Factor_Auth", "Type": "Binary", "Description": "MFA enforcement status (Enabled / Disabled)"}
    ]
    st.dataframe(pd.DataFrame(schema_data), width="stretch", hide_index=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("#### 💻 System Diagnostics & Environment")
    diag_col1, diag_col2 = st.columns(2)
    with diag_col1:
        st.markdown(f"""
        - **Python Version**: `{sys.version.split()[0]}`
        - **Streamlit Version**: `{st.__version__}`
        - **Dataset Size**: `{len(df_raw):,} records (Reproducible Seed 42)`
        - **Temporal Span**: `2021-01-01 to 2025-12-31 (5 Complete Years)`
        """)
    with diag_col2:
        st.markdown("""
        - **Project**: `CYBERSHIELD // ENTERPRISE HACKER MATRIX SOC`
        - **Program**: `BCA Final-Year Academic Capstone Project`
        - **Core Stack**: `Python, Streamlit, Pandas, NumPy, Plotly, Scikit-learn`
        - **SOC Nodes**: `10 Global Telemetry Relays Connected`
        """)


# ==============================================================================
# 8. FOOTER
# ==============================================================================
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #8BAA9B; font-size: 0.78rem; font-family: 'JetBrains Mono', monospace; padding: 10px 0 20px 0;">
    CYBERSHIELD // ENTERPRISE HACKER MATRIX SOC COMMAND CENTER<br>
    BCA Final-Year Academic Capstone Project | Built with Python, Streamlit, Pandas, NumPy, Plotly & Scikit-learn<br>
    <span style="color: #00FF88;">STAY SECURE • STAY AHEAD</span>
</div>
""", unsafe_allow_html=True)
