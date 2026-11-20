"""
4_department_risk.py
--------------------
Department Risk & Security Hygiene Scorecard: Multi-metric risk index scoring,
threat exposure profiles, and targeted organizational hardening recommendations.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

from dashboard.common import (
    load_data,
    apply_custom_css,
    render_sidebar_filters,
    SEVERITY_PALETTE
)

apply_custom_css()

st.markdown('<div class="main-header">🏢 Department Risk & Hygiene Scorecard</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Composite cybersecurity risk index calculation, cross-departmental exposure rankings, and targeted training roadmaps</div>', unsafe_allow_html=True)

df_raw = load_data()
if df_raw is None:
    st.error("🚨 Processed data not found.")
    st.stop()

filtered_df = render_sidebar_filters(df_raw)
if filtered_df.empty:
    st.warning("⚠️ No incidents match your selected filters.")
    st.stop()

# Calculate Department Security Scorecard
dept_records = []
for dept, group in filtered_df.groupby("Department"):
    total = len(group)
    crit = int((group["Severity"] == "Critical").sum())
    high = int((group["Severity"] == "High").sum())
    resolved = int((group["Status"] == "Resolved").sum())
    unresolved = total - resolved
    res_rate = round((resolved / total) * 100, 1) if total > 0 else 0.0
    
    resolved_hours = group[group["Status"] == "Resolved"]["Resolution_Hours"].dropna()
    avg_mttr = round(float(resolved_hours.mean()), 1) if len(resolved_hours) > 0 else 0.0

    # Composite Risk Index Formula (Higher = Higher Risk Exposure)
    # Weights: Critical (5.0), High (2.5), Baseline Incident Volume (1.0), MTTR Penalty (0.8), Resolution Rate Credit (-0.3)
    raw_risk = (total * 1.0) + (high * 2.5) + (crit * 5.0) + (avg_mttr * 0.8) - (res_rate * 0.2)
    risk_score = round(max(10.0, min(raw_risk, 100.0)), 1)

    dept_records.append({
        "Department": dept,
        "Total_Incidents": total,
        "Critical_Count": crit,
        "High_Count": high,
        "Resolved_Count": resolved,
        "Unresolved_Count": unresolved,
        "Resolution_Rate_Pct": res_rate,
        "Avg_MTTR_Hours": avg_mttr,
        "Risk_Score": risk_score
    })

scorecard_df = pd.DataFrame(dept_records).sort_values(by="Risk_Score", ascending=False).reset_index(drop=True)

# Top metrics
highest_risk_dept = scorecard_df.iloc[0]["Department"]
highest_risk_val = scorecard_df.iloc[0]["Risk_Score"]
fastest_res_dept = scorecard_df.sort_values(by="Avg_MTTR_Hours", ascending=True).iloc[0]["Department"]
fastest_res_val = scorecard_df.sort_values(by="Avg_MTTR_Hours", ascending=True).iloc[0]["Avg_MTTR_Hours"]

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Highest Risk Department</div>
        <div class="kpi-value" style="color: #DC2626;">{highest_risk_dept}</div>
        <div class="kpi-sub">Risk Index: {highest_risk_val} / 100</div>
    </div>
    """, unsafe_allow_html=True)

with m2:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Fastest Containment Unit</div>
        <div class="kpi-value" style="color: #16A34A;">{fastest_res_dept}</div>
        <div class="kpi-sub">Avg MTTR: {fastest_res_val} hrs</div>
    </div>
    """, unsafe_allow_html=True)

with m3:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Highest Unresolved Queue</div>
        <div class="kpi-value">{scorecard_df.sort_values(by='Unresolved_Count', ascending=False).iloc[0]['Department']}</div>
        <div class="kpi-sub">{scorecard_df['Unresolved_Count'].max()} Active Tickets</div>
    </div>
    """, unsafe_allow_html=True)

with m4:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Avg Department MTTR</div>
        <div class="kpi-value">{round(scorecard_df['Avg_MTTR_Hours'].mean(), 1)} hrs</div>
        <div class="kpi-sub">Cross-Unit Mean</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Row 1: Risk Ranking Chart & Exposure Table
r1_col1, r1_col2 = st.columns([1.3, 1.2])

with r1_col1:
    st.subheader("🛡️ Department Composite Risk Index Rankings")
    fig_risk = px.bar(
        scorecard_df.sort_values(by="Risk_Score", ascending=True),
        x="Risk_Score",
        y="Department",
        orientation="h",
        text="Risk_Score",
        color="Risk_Score",
        color_continuous_scale="Reds",
        labels={"Risk_Score": "Composite Risk Index (0-100)"}
    )
    fig_risk.update_layout(
        xaxis_title="Composite Risk Score (Higher = Elevated Exposure)",
        yaxis_title="",
        coloraxis_showscale=False,
        margin=dict(l=20, r=20, t=30, b=20)
    )
    st.plotly_chart(fig_risk, width="stretch")

with r1_col2:
    st.subheader("📊 Departmental Scorecard Table")
    st.dataframe(
        scorecard_df[[
            "Department",
            "Total_Incidents",
            "Critical_Count",
            "High_Count",
            "Resolution_Rate_Pct",
            "Avg_MTTR_Hours",
            "Risk_Score"
        ]],
        width="stretch",
        hide_index=True
    )

# Row 2: Deep-Dive Department Security Inspector
st.subheader("🔍 Department Security Profile Inspector")
selected_dept = st.selectbox("Select Department to inspect detailed threat posture:", options=scorecard_df["Department"].tolist())

dept_data = filtered_df[filtered_df["Department"] == selected_dept]
dept_row = scorecard_df[scorecard_df["Department"] == selected_dept].iloc[0]

d_col1, d_col2 = st.columns([1.2, 1.0])
with d_col1:
    dept_threats = dept_data["Incident_Type"].value_counts().reset_index()
    dept_threats.columns = ["Incident_Type", "Count"]
    fig_dthreat = px.bar(
        dept_threats,
        x="Incident_Type",
        y="Count",
        title=f"Attack Vector Distribution in {selected_dept}",
        color="Count",
        color_continuous_scale="Blues"
    )
    fig_dthreat.update_layout(
        xaxis_title="",
        yaxis_title="Incident Count",
        coloraxis_showscale=False,
        margin=dict(l=20, r=20, t=40, b=20)
    )
    st.plotly_chart(fig_dthreat, width="stretch")

with d_col2:
    st.markdown(f"#### 📋 Security Hygiene Checklist for {selected_dept}")
    st.markdown(f"""
    - **Total Incident Exposure**: `{int(dept_row['Total_Incidents'])}` security events recorded.
    - **High & Critical Urgency**: `{int(dept_row['Critical_Count'] + dept_row['High_Count'])}` urgent cases.
    - **Resolution Efficiency**: `{dept_row['Resolution_Rate_Pct']}%` resolved (Mean MTTR: `{dept_row['Avg_MTTR_Hours']} hrs`).
    """)
    
    st.markdown("##### 🎯 Recommended Departmental Actions:")
    if "Phishing" in dept_threats["Incident_Type"].values and dept_threats[dept_threats["Incident_Type"] == "Phishing"]["Count"].iloc[0] >= 3:
        st.warning("⚠️ **High Phishing Exposure**: Schedule automated monthly spear-phishing simulation drills and prompt employee awareness refreshers.")
    if "Suspicious Login" in dept_threats["Incident_Type"].values:
        st.info("🔑 **Identity & Access**: Audit MFA registration methods; mandate FIDO2 hardware security keys for administrative personnel.")
    if "Data Leak" in dept_threats["Incident_Type"].values:
        st.error("🚨 **Data Loss Prevention**: Implement client-side classification labels (Confidential / Public) and restrict USB transfer privileges.")
    if int(dept_row['Unresolved_Count']) > 4:
        st.info(f"⏳ **Active Backlog**: {int(dept_row['Unresolved_Count'])} open investigations require SLA triage prioritization.")
