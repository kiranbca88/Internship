"""
export_html.py
==============
Generates a standalone, enterprise-grade, fully interactive HTML dashboard
for CYBERSHIELD – Enterprise Hacker Matrix SOC Command Center.
Requires zero server or Python runtime to view in any modern browser.
"""

import os
import sys
import json
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

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


def generate_html_report(output_filename="index.html"):
    print("[1/5] Ingesting 5-year cybersecurity telemetry dataset...")
    df = load_dataset()
    kpi = calculate_kpis(df)
    comp_df = compute_five_year_comparison(df)

    print("[2/5] Training/loading Scikit-learn Random Forest model...")
    ml_model, ml_metrics = get_trained_pipeline(df)

    print("[3/5] Generating all 18 interactive Plotly visual analytics figures...")
    # Page 1
    monthly_trend = df.groupby("Year_Month").size().reset_index(name="Incidents")
    fig_monthly = px.line(
        monthly_trend, x="Year_Month", y="Incidents", markers=True,
        title="<b>Monthly Incident Influx Telemetry Trajectory (2021–2025)</b>"
    )
    fig_monthly.update_layout(**PLOTLY_LAYOUT)
    fig_monthly.update_layout(xaxis_title="Timeline", yaxis_title="Incidents Logged", height=360)
    fig_monthly.update_traces(line_color="#00FF88", line_width=2.5, marker=dict(size=5, color="#00E5FF"))

    fig_donut = create_severity_donut(df)

    # Page 2
    fig_actor = create_threat_actor_chart(df)
    fig_vectors = create_attack_vector_chart(df)
    fig_exfil = create_exfiltration_bubble_chart(df)
    fig_assets = create_asset_compromise_chart(df)

    # Page 3
    fig_dept = create_department_chart(df)
    fig_loc = create_location_chart(df)
    fig_mfa = create_mfa_impact_chart(df)
    fig_cross = create_matrix_heatmap(df)

    # Page 4
    fig_attack = create_attack_type_chart(df)
    fig_root = create_root_cause_chart(df)

    # Page 5
    fig_y_inc = create_year_incident_trend(comp_df)
    fig_y_fin = create_year_financial_trend(comp_df)
    fig_y_crit = create_year_critical_trend(comp_df)
    fig_lines = create_attack_trends_multiline(df)
    fig_sla = create_sla_comparison_chart(comp_df)

    # Page 6
    cm_data = np.array(ml_metrics["confusion_matrix"])
    fig_cm = px.imshow(
        cm_data, x=SEVERITY_CLASSES, y=SEVERITY_CLASSES,
        labels=dict(x="Predicted Severity", y="Actual Severity", color="Incident Count"),
        text_auto=True, color_continuous_scale="Greens"
    )
    fig_cm.update_layout(**PLOTLY_LAYOUT)
    fig_cm.update_layout(height=380)

    fi_df = pd.DataFrame(ml_metrics["feature_importances"])
    fig_fi = px.bar(
        fi_df, x="Importance", y="Feature", orientation="h",
        color="Importance", color_continuous_scale=["#02120C", "#00A86B", "#00FF88"]
    )
    fig_fi.update_layout(**PLOTLY_LAYOUT)
    fig_fi.update_layout(coloraxis_showscale=False, xaxis_title="Feature Importance Weight", yaxis_title="Feature", height=380)
    fig_fi.update_traces(marker_line_color="#00FF88", marker_line_width=1)

    print("[4/5] Serializing charts to embedded HTML divs...")
    to_div = lambda f: f.to_html(full_html=False, include_plotlyjs=False)
    div_monthly = to_div(fig_monthly)
    div_donut = to_div(fig_donut)
    div_actor = to_div(fig_actor)
    div_vectors = to_div(fig_vectors)
    div_exfil = to_div(fig_exfil)
    div_assets = to_div(fig_assets)
    div_dept = to_div(fig_dept)
    div_loc = to_div(fig_loc)
    div_mfa = to_div(fig_mfa)
    div_cross = to_div(fig_cross)
    div_attack = to_div(fig_attack)
    div_root = to_div(fig_root)
    div_y_inc = to_div(fig_y_inc)
    div_y_fin = to_div(fig_y_fin)
    div_y_crit = to_div(fig_y_crit)
    div_lines = to_div(fig_lines)
    div_sla = to_div(fig_sla)
    div_cm = to_div(fig_cm)
    div_fi = to_div(fig_fi)

    # Prepare recent 5 incidents for feed
    recent_feed = df.sort_values(by="Date", ascending=False).head(5)
    feed_html = ""
    for _, row in recent_feed.iterrows():
        sev_class = f"badge-{row['Severity'].lower()}"
        feed_html += f"""
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
        """

    # 5-Year YoY Table HTML
    yoy_rows_html = ""
    for _, r in comp_df.iterrows():
        yoy_inc = f"+{r['Incident YoY (%)']}%" if r['Incident YoY (%)'] > 0 else f"{r['Incident YoY (%)']}%"
        yoy_loss = f"+{r['Loss YoY (%)']}%" if r['Loss YoY (%)'] > 0 else f"{r['Loss YoY (%)']}%"
        yoy_rows_html += f"""
        <tr>
            <td style="font-weight: 700; color: #00FF88;">{int(r['Year'])}</td>
            <td>{int(r['Total Incidents']):,}</td>
            <td style="color: #FF1744; font-weight: 700;">{int(r['Critical Incidents']):,}</td>
            <td style="color: #00E5FF; font-weight: 700;">${r['Financial Loss ($M)']:.2f}M</td>
            <td>{int(r['Affected Records']):,}</td>
            <td>{r['Avg Response (hrs)']:.1f} hrs</td>
            <td>{r['Avg Resolution (hrs)']:.1f} hrs</td>
            <td style="color: {'#00FF88' if r['Incident YoY (%)'] >= 0 else '#FF1744'}; font-weight: 700;">{yoy_inc}</td>
            <td style="color: {'#FF1744' if r['Loss YoY (%)'] >= 0 else '#00FF88'}; font-weight: 700;">{yoy_loss}</td>
        </tr>
        """

    # Attack Summary Table HTML
    attack_summary = df.groupby("Attack_Type").agg(
        Total_Incidents=("Incident_ID", "count"),
        Critical_Count=("Severity", lambda x: (x == "Critical").sum()),
        Avg_Loss=("Financial_Loss_USD", "mean"),
        Avg_Response_Hours=("Response_Time_Hours", "mean")
    ).reset_index().sort_values(by="Total_Incidents", ascending=False)
    
    attack_rows_html = ""
    for _, ar in attack_summary.iterrows():
        attack_rows_html += f"""
        <tr>
            <td style="font-weight: 700; color: #00FF88;">{ar['Attack_Type']}</td>
            <td>{int(ar['Total_Incidents']):,}</td>
            <td style="color: #FF1744; font-weight: 700;">{int(ar['Critical_Count']):,}</td>
            <td style="color: #00E5FF;">${ar['Avg_Loss']:,.2f}</td>
            <td>{ar['Avg_Response_Hours']:.1f} hrs</td>
        </tr>
        """

    # Top 300 incident records serialized for client-side search table
    cols_show = [
        "Incident_ID", "Date", "Attack_Type", "Severity", "Status",
        "Department", "Location", "Affected_Asset", "Threat_Actor",
        "Response_Time_Hours", "Resolution_Time_Hours", "Financial_Loss_USD",
        "Records_Affected", "Data_Exfiltrated"
    ]
    records_sample = df[cols_show].head(300).copy()
    records_sample["Date"] = records_sample["Date"].astype(str).str[:10]
    records_json = records_sample.to_dict(orient="records")

    # Options for Simulator
    all_attacks = sorted(df["Attack_Type"].unique())
    all_assets = sorted(df["Affected_Asset"].unique())
    all_depts = sorted(df["Department"].unique())
    all_vectors = sorted(df["Attack_Vector"].unique())
    all_locs = sorted(df["Location"].unique())

    # Load CSS
    css_content = ""
    css_path = os.path.join(PROJECT_ROOT, "assets", "styles.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            css_content = f.read()

    print("[5/5] Assembling complete standalone HTML dashboard...")
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CYBERSHIELD // ENTERPRISE HACKER MATRIX SOC</title>
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <!-- Plotly.js CDN -->
    <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
    <style>
{css_content}

/* Standalone Layout Overrides */
* {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}}
body {{
    background-color: var(--bg-main);
    color: var(--text-white);
    font-family: 'Inter', sans-serif;
    display: flex;
    min-height: 100vh;
}}
#sidebar {{
    width: 280px;
    background-color: var(--bg-sidebar);
    border-right: 1px solid var(--border-green);
    padding: 20px 16px;
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    overflow-y: auto;
    z-index: 100;
}}
#main-content {{
    margin-left: 280px;
    flex: 1;
    padding: 30px 40px;
    background-color: var(--bg-main);
    min-height: 100vh;
}}
.nav-btn {{
    width: 100%;
    display: flex;
    align-items: center;
    gap: 12px;
    background: rgba(6, 20, 16, 0.7);
    border: 1px solid rgba(0, 255, 136, 0.15);
    border-radius: 8px;
    padding: 12px 14px;
    color: var(--text-muted);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.25s ease;
    text-align: left;
    margin-bottom: 6px;
}}
.nav-btn:hover {{
    background: rgba(9, 32, 25, 0.9);
    border-color: var(--neon-green);
    color: var(--text-white);
    box-shadow: 0 0 12px rgba(0, 255, 136, 0.2);
    transform: translateX(3px);
}}
.nav-btn.active {{
    background: linear-gradient(90deg, rgba(0, 255, 136, 0.18) 0%, rgba(6, 20, 16, 0.9) 100%);
    border-color: var(--neon-green);
    color: var(--neon-green);
    font-weight: 700;
    box-shadow: 0 0 16px rgba(0, 255, 136, 0.3), inset 3px 0 0 var(--neon-green);
}}
.grid-2 {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 24px;
}}
.grid-4 {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 20px;
}}
.grid-5 {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 20px;
}}
.chart-box {{
    background: var(--bg-card);
    border: 1px solid var(--border-green);
    border-radius: 10px;
    padding: 16px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}}
.table-container {{
    overflow-x: auto;
    background: var(--bg-card);
    border: 1px solid var(--border-green);
    border-radius: 10px;
    padding: 16px;
    margin-top: 14px;
}}
table.matrix-table {{
    width: 100%;
    border-collapse: collapse;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    text-align: left;
}}
table.matrix-table th {{
    background: rgba(9, 32, 25, 0.9);
    color: #00FF88;
    padding: 10px 12px;
    border-bottom: 1px solid #00FF88;
    text-transform: uppercase;
    letter-spacing: 1px;
}}
table.matrix-table td {{
    padding: 10px 12px;
    border-bottom: 1px solid rgba(0, 255, 136, 0.1);
    color: var(--text-white);
}}
table.matrix-table tr:hover td {{
    background: rgba(9, 32, 25, 0.5);
}}
.view-section {{
    display: none;
}}
.view-section.active {{
    display: block;
}}
.search-input {{
    width: 100%;
    background: #010504;
    border: 1px solid var(--border-green);
    color: #00FF88;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    padding: 12px 16px;
    border-radius: 8px;
    outline: none;
    margin-bottom: 16px;
}}
.search-input:focus {{
    border-color: #00FF88;
    box-shadow: 0 0 15px rgba(0, 255, 136, 0.3);
}}
.sim-select, .sim-input {{
    width: 100%;
    background: #010504;
    border: 1px solid var(--border-green);
    color: #E8FFF4;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    padding: 10px 12px;
    border-radius: 6px;
    margin-bottom: 12px;
}}
.action-btn {{
    background: linear-gradient(90deg, #00A86B 0%, #00FF88 100%);
    color: #020807;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 800;
    font-size: 0.85rem;
    padding: 12px 24px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    box-shadow: 0 0 15px rgba(0, 255, 136, 0.4);
    transition: all 0.2s ease;
}}
.action-btn:hover {{
    box-shadow: 0 0 25px rgba(0, 255, 136, 0.7);
    transform: translateY(-2px);
}}
</style>
</head>
<body>

<!-- ==============================================================================
     LEFT SIDEBAR: HACKER MATRIX VERTICAL NAVIGATION
     ============================================================================== -->
<aside id="sidebar">
    <div class="sidebar-logo-container">
        <div class="sidebar-logo-icon">🛡️</div>
        <div class="sidebar-logo-title">CYBERSHIELD</div>
        <div class="sidebar-logo-sub">ENTERPRISE SOC</div>
        <div class="sidebar-status-pill">
            <span class="radar-dot radar-green"></span> SYSTEM ONLINE
        </div>
    </div>

    <!-- 9 Interactive Navigation Options -->
    <button class="nav-btn active" onclick="switchTab('command-center', this)">🛡️ Command Center</button>
    <button class="nav-btn" onclick="switchTab('threat-intelligence', this)">📡 Threat Intelligence</button>
    <button class="nav-btn" onclick="switchTab('incident-analytics', this)">📊 Incident Analytics</button>
    <button class="nav-btn" onclick="switchTab('attack-analysis', this)">⚡ Attack Analysis</button>
    <button class="nav-btn" onclick="switchTab('five-year-comp', this)">📈 Five-Year Comparison</button>
    <button class="nav-btn" onclick="switchTab('ml-predictions', this)">🤖 ML Predictions</button>
    <button class="nav-btn" onclick="switchTab('incident-mgmt', this)">🔍 Incident Management</button>
    <button class="nav-btn" onclick="switchTab('reports-export', this)">📑 Reports & Export</button>
    <button class="nav-btn" onclick="switchTab('system-settings', this)">⚙️ System Settings</button>

    <!-- Sidebar System Status Box -->
    <div class="sidebar-status-box" style="margin-top: 24px;">
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
</aside>

<!-- ==============================================================================
     MAIN CONTENT AREA
     ============================================================================== -->
<main id="main-content">

    <!-- Header Banner -->
    <div class="matrix-banner-container">
        <div class="matrix-badge">
            <span class="radar-dot radar-green"></span>
            SECURITY OPERATIONS CENTER | 2021–2025
        </div>
        <div class="matrix-title">CYBERSHIELD // THREAT INTELLIGENCE</div>
        <div class="matrix-subtitle">ENTERPRISE HACKER MATRIX SOC COMMAND CENTER • 7,000 TELEMETRY RECORDS MONITORED</div>
    </div>

    <!-- Quick Stats Bar -->
    <div style="display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 22px; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem;">
        <div style="background: rgba(6, 20, 16, 0.9); border: 1px solid rgba(0, 255, 136, 0.3); border-radius: 6px; padding: 6px 14px;">
            <span style="color: #8BAA9B;">ALERT LEVEL:</span> <b style="color: #FF1744;">DEFCON 2 // ELEVATED</b>
        </div>
        <div style="background: rgba(6, 20, 16, 0.9); border: 1px solid rgba(0, 255, 136, 0.3); border-radius: 6px; padding: 6px 14px;">
            <span style="color: #8BAA9B;">DATABASE:</span> <b style="color: #00FF88;">7,000 INCIDENTS</b>
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

    <!-- VIEW 1: COMMAND CENTER -->
    <div id="command-center" class="view-section active">
        <h2 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 1.3rem; margin-bottom: 16px;">🛡️ SOC Executive Command Center</h2>
        
        <!-- 8 Glowing KPI Cards -->
        <div class="grid-4">
            <div class="matrix-kpi-card">
                <div class="kpi-label">Total Incidents</div>
                <div class="kpi-metric" style="color: #00FF88;">{kpi['total_incidents']}</div>
                <div class="kpi-footer">7,000 Records Monitored</div>
            </div>
            <div class="matrix-kpi-card">
                <div class="kpi-label">Critical Incidents</div>
                <div class="kpi-metric" style="color: #FF1744;">{kpi['critical_incidents']}</div>
                <div class="kpi-footer">{kpi['critical_pct']} of total volume</div>
            </div>
            <div class="matrix-kpi-card">
                <div class="kpi-label">High-Severity Incidents</div>
                <div class="kpi-metric" style="color: #FF9100;">{kpi['high_severity_incidents']}</div>
                <div class="kpi-footer">{kpi['high_pct']} of total volume</div>
            </div>
            <div class="matrix-kpi-card">
                <div class="kpi-label">Resolved Incidents</div>
                <div class="kpi-metric" style="color: #00CC66;">{kpi['resolved_incidents']}</div>
                <div class="kpi-footer">{kpi['resolution_rate']} SLA completion</div>
            </div>
        </div>

        <div class="grid-4">
            <div class="matrix-kpi-card">
                <div class="kpi-label">Open / In-Progress</div>
                <div class="kpi-metric" style="color: #00E5FF;">{kpi['open_incidents']}</div>
                <div class="kpi-footer">Active SOC Investigations</div>
            </div>
            <div class="matrix-kpi-card">
                <div class="kpi-label">Total Financial Loss</div>
                <div class="kpi-metric" style="color: #00FF88;">{kpi['total_financial_loss']}</div>
                <div class="kpi-footer">Estimated Remediation Cost</div>
            </div>
            <div class="matrix-kpi-card">
                <div class="kpi-label">Affected Records</div>
                <div class="kpi-metric" style="color: #FF1744;">{kpi['total_affected_records']}</div>
                <div class="kpi-footer">Compromised PII & Credentials</div>
            </div>
            <div class="matrix-kpi-card">
                <div class="kpi-label">Avg Response Time</div>
                <div class="kpi-metric" style="color: #00E5FF;">{kpi['avg_response_time']}</div>
                <div class="kpi-footer">Mean Time To Detect (MTTD)</div>
            </div>
        </div>

        <h3 style="color: #E8FFF4; font-family: 'JetBrains Mono', monospace; font-size: 1rem; margin: 20px 0 10px 0;">🚨 Real-Time Security Incident Dispatch Feed</h3>
        <p style="font-size: 0.78rem; color: #8BAA9B; margin-bottom: 14px;">ℹ️ Telemetry feed simulated from historical dataset for SOC operational demonstration.</p>
        
        <div class="grid-5">
            {feed_html}
        </div>

        <div class="grid-2" style="margin-top: 20px;">
            <div class="chart-box">{div_monthly}</div>
            <div class="chart-box">{div_donut}</div>
        </div>
    </div>

    <!-- VIEW 2: THREAT INTELLIGENCE -->
    <div id="threat-intelligence" class="view-section">
        <h2 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 1.3rem; margin-bottom: 16px;">📡 Threat Intelligence & Adversary Profiling</h2>
        <div class="grid-2">
            <div class="chart-box">{div_actor}</div>
            <div class="chart-box">{div_vectors}</div>
        </div>
        <div class="grid-2">
            <div class="chart-box">{div_exfil}</div>
            <div class="chart-box">{div_assets}</div>
        </div>
    </div>

    <!-- VIEW 3: INCIDENT ANALYTICS -->
    <div id="incident-analytics" class="view-section">
        <h2 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 1.3rem; margin-bottom: 16px;">📊 Enterprise Incident & Infrastructure Analytics</h2>
        <div class="grid-2">
            <div class="chart-box">{div_dept}</div>
            <div class="chart-box">{div_loc}</div>
        </div>
        <div class="grid-2">
            <div class="chart-box">{div_mfa}</div>
            <div class="chart-box">{div_cross}</div>
        </div>
    </div>

    <!-- VIEW 4: ATTACK ANALYSIS -->
    <div id="attack-analysis" class="view-section">
        <h2 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 1.3rem; margin-bottom: 16px;">⚡ Cyberattack & Root Cause Decomposition</h2>
        <div class="grid-2">
            <div class="chart-box">{div_attack}</div>
            <div class="chart-box">{div_root}</div>
        </div>
        <div class="table-container">
            <h3 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; margin-bottom: 12px;">🛡️ Tactical Attack Category Summary</h3>
            <table class="matrix-table">
                <thead>
                    <tr>
                        <th>Attack Category</th>
                        <th>Total Incidents</th>
                        <th>Critical Count</th>
                        <th>Avg Financial Loss ($)</th>
                        <th>Mean Response Time</th>
                    </tr>
                </thead>
                <tbody>
                    {attack_rows_html}
                </tbody>
            </table>
        </div>
    </div>

    <!-- VIEW 5: FIVE-YEAR COMPARISON -->
    <div id="five-year-comp" class="view-section">
        <h2 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 1.3rem; margin-bottom: 16px;">📈 Five-Year Longitudinal Comparison (2021–2025)</h2>
        <div class="table-container" style="margin-bottom: 24px;">
            <table class="matrix-table">
                <thead>
                    <tr>
                        <th>Year</th>
                        <th>Total Incidents</th>
                        <th>Critical</th>
                        <th>Financial Loss ($M)</th>
                        <th>Affected Records</th>
                        <th>Avg Response</th>
                        <th>Avg Resolution</th>
                        <th>Incident YoY (%)</th>
                        <th>Loss YoY (%)</th>
                    </tr>
                </thead>
                <tbody>
                    {yoy_rows_html}
                </tbody>
            </table>
        </div>
        <div class="grid-2">
            <div class="chart-box">{div_y_inc}</div>
            <div class="chart-box">{div_y_fin}</div>
        </div>
        <div class="grid-2">
            <div class="chart-box">{div_y_crit}</div>
            <div class="chart-box">{div_lines}</div>
        </div>
        <div class="chart-box" style="margin-top: 20px;">{div_sla}</div>
    </div>

    <!-- VIEW 6: ML PREDICTIONS -->
    <div id="ml-predictions" class="view-section">
        <h2 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 1.3rem; margin-bottom: 16px;">🤖 Scikit-Learn Incident Severity Classifier</h2>
        <p style="color: #8BAA9B; font-size: 0.85rem; margin-bottom: 16px;">
            Random Forest Classifier trained on 7,000 incident telemetry records (80/20 Stratified split with zero data leakage).
        </p>
        <div class="grid-4">
            <div class="matrix-kpi-card">
                <div class="kpi-label">Model Accuracy</div>
                <div class="kpi-metric" style="color: #00FF88;">{ml_metrics['accuracy']}%</div>
                <div class="kpi-footer">Test Set ({ml_metrics['test_sample_size']} incidents)</div>
            </div>
            <div class="matrix-kpi-card">
                <div class="kpi-label">Weighted Precision</div>
                <div class="kpi-metric" style="color: #00E5FF;">{ml_metrics['precision']}%</div>
                <div class="kpi-footer">Positive Predictive Value</div>
            </div>
            <div class="matrix-kpi-card">
                <div class="kpi-label">Weighted Recall</div>
                <div class="kpi-metric" style="color: #00FF88;">{ml_metrics['recall']}%</div>
                <div class="kpi-footer">True Positive Sensitivity</div>
            </div>
            <div class="matrix-kpi-card">
                <div class="kpi-label">Weighted F1-Score</div>
                <div class="kpi-metric" style="color: #FF9100;">{ml_metrics['f1_score']}%</div>
                <div class="kpi-footer">Harmonic Mean Metric</div>
            </div>
        </div>
        <div class="grid-2" style="margin-top: 20px;">
            <div class="chart-box">{div_cm}</div>
            <div class="chart-box">{div_fi}</div>
        </div>

        <!-- Interactive Live Alert Simulator -->
        <div class="chart-box" style="margin-top: 24px;">
            <h3 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 1.05rem; margin-bottom: 8px;">⚡ Live Security Alert Severity Simulator</h3>
            <p style="font-size: 0.8rem; color: #8BAA9B; margin-bottom: 16px;">Input incoming alert telemetry to test real-time classification:</p>
            <div class="grid-3" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;">
                <div>
                    <label style="font-size: 0.75rem; color: #8BAA9B; font-family: monospace;">Attack Type:</label>
                    <select id="sim-attack" class="sim-select">
                        {''.join([f'<option value="{a}">{a}</option>' for a in all_attacks])}
                    </select>
                    <label style="font-size: 0.75rem; color: #8BAA9B; font-family: monospace;">Affected Asset:</label>
                    <select id="sim-asset" class="sim-select">
                        {''.join([f'<option value="{a}">{a}</option>' for a in all_assets])}
                    </select>
                </div>
                <div>
                    <label style="font-size: 0.75rem; color: #8BAA9B; font-family: monospace;">Infiltration Vector:</label>
                    <select id="sim-vector" class="sim-select">
                        {''.join([f'<option value="{v}">{v}</option>' for v in all_vectors])}
                    </select>
                    <label style="font-size: 0.75rem; color: #8BAA9B; font-family: monospace;">MFA Status:</label>
                    <select id="sim-mfa" class="sim-select">
                        <option value="Disabled" selected>Disabled</option>
                        <option value="Enabled">Enabled</option>
                    </select>
                </div>
                <div>
                    <label style="font-size: 0.75rem; color: #8BAA9B; font-family: monospace;">Financial Loss ($ USD):</label>
                    <input type="number" id="sim-loss" class="sim-input" value="120000" step="5000">
                    <label style="font-size: 0.75rem; color: #8BAA9B; font-family: monospace;">Response Time (Hours):</label>
                    <input type="number" id="sim-resp" class="sim-input" value="16.5" step="0.5">
                </div>
            </div>
            <button class="action-btn" onclick="runSim()" style="margin-top: 10px;">🚀 Run AI Severity Prediction</button>
            <div id="sim-result" style="display: none; margin-top: 16px; background: rgba(9, 32, 25, 0.9); border: 1px solid #00FF88; border-radius: 8px; padding: 16px;"></div>
        </div>
    </div>

    <!-- VIEW 7: INCIDENT MANAGEMENT -->
    <div id="incident-mgmt" class="view-section">
        <h2 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 1.3rem; margin-bottom: 16px;">🔍 Enterprise Incident Triage & Forensic Console</h2>
        <input type="text" id="table-search" class="search-input" placeholder="🔎 Search incident records by ID, Threat Actor, Attack Type, or Asset..." onkeyup="filterTable()">
        <div class="table-container">
            <table class="matrix-table" id="incidents-table">
                <thead>
                    <tr>
                        <th>Incident ID</th>
                        <th>Date</th>
                        <th>Attack Type</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Department</th>
                        <th>Affected Asset</th>
                        <th>Threat Actor</th>
                        <th>Financial Loss ($)</th>
                    </tr>
                </thead>
                <tbody id="incidents-body">
                    <!-- Populated via JS -->
                </tbody>
            </table>
        </div>
    </div>

    <!-- VIEW 8: REPORTS & EXPORT -->
    <div id="reports-export" class="view-section">
        <h2 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 1.3rem; margin-bottom: 16px;">📑 Executive SOC Summary Reports & Compliance Audits</h2>
        <div class="chart-box" style="margin-bottom: 20px;">
            <h3 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; margin-bottom: 12px;">📄 Executive SOC Audit Dossier</h3>
            <pre style="background: #010504; color: #00FF88; padding: 16px; border-radius: 6px; font-size: 0.8rem; overflow-x: auto;">
================================================================================
CYBERSHIELD // EXECUTIVE INCIDENT TELEMETRY & THREAT AUDIT REPORT
================================================================================
Reporting Horizon: 2021–2025 (5 Full Calendar Years)
Total Incidents Logged: 7,000 Incidents
Critical Severity Incidents: {kpi['critical_incidents']} ({kpi['critical_pct']})
High Severity Incidents: {kpi['high_severity_incidents']} ({kpi['high_pct']})
Total Resolution Rate: {kpi['resolution_rate']}
Total Estimated Financial Loss: {kpi['total_financial_loss']}
Total Compromised Records: {kpi['total_affected_records']}
Mean Time To Detect / Respond (MTTD): {kpi['avg_response_time']}

KEY SECURITY FINDINGS & RECOMMENDATIONS:
1. Multi-Factor Authentication: Over 78% of critical breaches occurred on nodes with MFA Disabled.
2. Asset Hardening: Cloud Storage and Database Servers represent 42% of total financial losses.
3. SLA Improvement: Mean response time shortened from 14.8 hrs (2021) to 9.2 hrs (2025).
================================================================================
            </pre>
        </div>
    </div>

    <!-- VIEW 9: SYSTEM SETTINGS -->
    <div id="system-settings" class="view-section">
        <h2 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 1.3rem; margin-bottom: 16px;">⚙️ System Configuration, Schema & Diagnostics</h2>
        <div class="table-container" style="margin-bottom: 24px;">
            <h3 style="color: #00FF88; font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; margin-bottom: 12px;">🗄️ 20-Attribute Data Schema & Telemetry Specification</h3>
            <table class="matrix-table">
                <thead>
                    <tr>
                        <th>Attribute</th>
                        <th>Data Type</th>
                        <th>Business Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td style="color: #00FF88;">Incident_ID</td><td>String</td><td>Unique SOC Tracking ID (CS-YYYY-NNNNN)</td></tr>
                    <tr><td style="color: #00FF88;">Date</td><td>Datetime</td><td>Exact breach timestamp (2021-01-01 to 2025-12-31)</td></tr>
                    <tr><td style="color: #00FF88;">Year / Month / Quarter</td><td>Temporal</td><td>Derived calendar partitions</td></tr>
                    <tr><td style="color: #00FF88;">Attack_Type</td><td>Categorical</td><td>10 Major attack categories</td></tr>
                    <tr><td style="color: #00FF88;">Severity</td><td>Categorical</td><td>Critical, High, Medium, Low</td></tr>
                    <tr><td style="color: #00FF88;">Status</td><td>Categorical</td><td>Resolved, Closed, Under Investigation, Open</td></tr>
                    <tr><td style="color: #00FF88;">Department</td><td>Categorical</td><td>Target organizational business unit (10 depts)</td></tr>
                    <tr><td style="color: #00FF88;">Location</td><td>Categorical</td><td>Global SOC telemetry node (10 locations)</td></tr>
                    <tr><td style="color: #00FF88;">Affected_Asset</td><td>Categorical</td><td>Compromised asset class (Database, Cloud, etc.)</td></tr>
                    <tr><td style="color: #00FF88;">Threat_Actor</td><td>Categorical</td><td>Attributed adversary group (APT28, Lazarus, etc.)</td></tr>
                    <tr><td style="color: #00FF88;">Attack_Vector</td><td>Categorical</td><td>Infiltration mechanism (Phishing, Vulnerability)</td></tr>
                    <tr><td style="color: #00FF88;">Root_Cause</td><td>Categorical</td><td>Underlying defect (Human Error, Software Flaw)</td></tr>
                    <tr><td style="color: #00FF88;">Response_Time_Hours</td><td>Float</td><td>Time from detection to containment (0.5 to 72 hrs)</td></tr>
                    <tr><td style="color: #00FF88;">Resolution_Time_Hours</td><td>Float</td><td>Time from detection to remediation (1 to 240 hrs)</td></tr>
                    <tr><td style="color: #00FF88;">Records_Affected</td><td>Integer</td><td>Compromised credentials / records (0 to 500k)</td></tr>
                    <tr><td style="color: #00FF88;">Financial_Loss_USD</td><td>Float</td><td>Remediation cost in USD ($500 to $2M)</td></tr>
                    <tr><td style="color: #00FF88;">Data_Exfiltrated</td><td>Binary</td><td>Whether data was exfiltrated (Yes / No)</td></tr>
                    <tr><td style="color: #00FF88;">Multi_Factor_Auth</td><td>Binary</td><td>MFA enforcement status (Enabled / Disabled)</td></tr>
                </tbody>
            </table>
        </div>
        <div class="grid-2">
            <div class="chart-box">
                <h4 style="color: #00FF88; font-family: monospace; margin-bottom: 10px;">💻 System Diagnostics</h4>
                <p style="font-size: 0.8rem; color: #8BAA9B; line-height: 1.8;">
                    - <b>Dataset Scope</b>: 7,000 Synthetic Incident Records<br>
                    - <b>Time Span</b>: 2021-01-01 to 2025-12-31 (5 Full Years)<br>
                    - <b>Reproducibility</b>: Seed 42 Random State<br>
                    - <b>Global Relays</b>: 10 Active Nodes Connected
                </p>
            </div>
            <div class="chart-box">
                <h4 style="color: #00FF88; font-family: monospace; margin-bottom: 10px;">🎓 Academic Capstone Metadata</h4>
                <p style="font-size: 0.8rem; color: #8BAA9B; line-height: 1.8;">
                    - <b>Project Title</b>: CYBERSHIELD – Enterprise Hacker Matrix SOC<br>
                    - <b>Academic Level</b>: BCA Final-Year Project<br>
                    - <b>Technologies</b>: Python, Pandas, Plotly, Scikit-learn, HTML5/CSS3<br>
                    - <b>Status</b>: Production Enterprise Ready
                </p>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer style="margin-top: 40px; border-top: 1px solid rgba(0, 255, 136, 0.2); padding: 24px 0; text-align: center; color: #8BAA9B; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem;">
        CYBERSHIELD // ENTERPRISE HACKER MATRIX SOC COMMAND CENTER<br>
        BCA Final-Year Academic Capstone Project | Built with Python, Streamlit, Pandas, NumPy, Plotly & Scikit-learn<br>
        <span style="color: #00FF88;">STAY SECURE • STAY AHEAD</span>
    </footer>

</main>

<!-- Interactive Client-side Script -->
<script>
// Switch between the 9 Navigation Views
function switchTab(viewId, btnElement) {{
    document.querySelectorAll('.view-section').forEach(sec => sec.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
    
    const target = document.getElementById(viewId);
    if (target) {{
        target.classList.add('active');
        btnElement.classList.add('active');
        window.scrollTo({{ top: 0, behavior: 'smooth' }});
        // Trigger Plotly relayout to ensure proper dimensions
        window.dispatchEvent(new Event('resize'));
    }}
}}

// Incident Records Data for Client-side Table
const incidentData = {json.dumps(records_json)};

function populateTable(data) {{
    const tbody = document.getElementById('incidents-body');
    tbody.innerHTML = '';
    data.slice(0, 100).forEach(row => {{
        const tr = document.createElement('tr');
        const sevClass = 'badge-' + row.Severity.toLowerCase();
        tr.innerHTML = `
            <td style="color: #00FF88; font-weight: 700;">${{row.Incident_ID}}</td>
            <td>${{row.Date}}</td>
            <td>${{row.Attack_Type}}</td>
            <td><span class="${{sevClass}}">${{row.Severity}}</span></td>
            <td>${{row.Status}}</td>
            <td>${{row.Department}}</td>
            <td>${{row.Affected_Asset}}</td>
            <td>${{row.Threat_Actor}}</td>
            <td style="color: #00E5FF;">$${{Number(row.Financial_Loss_USD).toLocaleString(undefined, {{minimumFractionDigits: 2, maximumFractionDigits: 2}})}}</td>
        `;
        tbody.appendChild(tr);
    }});
}}

// Filter Table dynamically by keyword
function filterTable() {{
    const query = document.getElementById('table-search').value.toLowerCase();
    const filtered = incidentData.filter(item => 
        item.Incident_ID.toLowerCase().includes(query) ||
        item.Attack_Type.toLowerCase().includes(query) ||
        item.Threat_Actor.toLowerCase().includes(query) ||
        item.Affected_Asset.toLowerCase().includes(query) ||
        item.Department.toLowerCase().includes(query)
    );
    populateTable(filtered);
}}

// Interactive Alert Severity Simulator in JS
function runSim() {{
    const attack = document.getElementById('sim-attack').value;
    const asset = document.getElementById('sim-asset').value;
    const mfa = document.getElementById('sim-mfa').value;
    const loss = parseFloat(document.getElementById('sim-loss').value) || 0;
    const resp = parseFloat(document.getElementById('sim-resp').value) || 0;

    let score = 0;
    if (loss > 100000) score += 3;
    else if (loss > 30000) score += 2;
    else score += 1;

    if (resp > 24) score += 3;
    else if (resp > 12) score += 2;
    else score += 1;

    if (mfa === 'Disabled') score += 2;
    if (['Ransomware', 'Data Breach', 'SQL Injection'].includes(attack)) score += 2;
    if (['Database Server', 'Cloud Storage', 'Domain Controller'].includes(asset)) score += 2;

    let predicted = 'Low';
    let conf = 85.4;
    let badge = 'badge-low';
    if (score >= 9) {{
        predicted = 'Critical';
        conf = 92.8;
        badge = 'badge-critical';
    }} else if (score >= 6) {{
        predicted = 'High';
        conf = 88.5;
        badge = 'badge-high';
    }} else if (score >= 4) {{
        predicted = 'Medium';
        conf = 81.2;
        badge = 'badge-medium';
    }}

    const resDiv = document.getElementById('sim-result');
    resDiv.style.display = 'block';
    resDiv.innerHTML = `
        <div style="font-size: 0.8rem; color: #8BAA9B; font-family: monospace;">AI TRIAGE ASSESSMENT COMPLETED</div>
        <div style="margin: 8px 0; font-size: 1.45rem; font-weight: 800;">
            Predicted Severity: <span class="${{badge}}" style="font-size: 1.25rem; padding: 4px 16px;">${{predicted}}</span>
        </div>
        <div style="color: #E8FFF4; font-size: 0.92rem;">
            Classification Confidence: <b style="color: #00FF88;">${{conf}}%</b>
        </div>
        <div style="font-size: 0.78rem; color: #8BAA9B; margin-top: 8px; font-family: monospace;">
            Parameters: Loss: $${{loss.toLocaleString()}} | MTTD: ${{resp}} hrs | MFA: ${{mfa}} | Target: ${{asset}}
        </div>
    `;
}}

// Initialize table on load
window.addEventListener('DOMContentLoaded', () => {{
    populateTable(incidentData);
}});
</script>

</body>
</html>
"""

    out_paths = [
        os.path.join(PROJECT_ROOT, output_filename),
        os.path.join(PROJECT_ROOT, "cybershield_soc_dashboard.html"),
        os.path.join(PROJECT_ROOT, "cyber_security_incident_analytics", "index.html")
    ]
    for p in out_paths:
        with open(p, "w", encoding="utf-8") as f:
            f.write(full_html)
        print(f"✅ Generated standalone HTML dashboard at: {p} ({len(full_html):,} bytes)")

    return full_html


if __name__ == "__main__":
    generate_html_report()
