"""
1_overview.py
-------------
Executive Overview Dashboard: High-level KPIs, incident arrivals, severity splits,
and cross-departmental exposure metrics.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from dashboard.common import (
    load_data,
    apply_custom_css,
    render_sidebar_filters,
    SEVERITY_PALETTE,
    STATUS_PALETTE
)

apply_custom_css()

st.markdown('<div class="main-header">📊 Executive Incident Operations Overview</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Strategic Security Operations Center (SOC) intelligence, triage metrics, and high-level KPI tracking</div>', unsafe_allow_html=True)

df_raw = load_data()
if df_raw is None:
    st.error("🚨 Processed data not found. Please run the data pipeline first.")
    st.stop()

filtered_df = render_sidebar_filters(df_raw)

if filtered_df.empty:
    st.warning("⚠️ No incidents match your selected filter criteria. Please expand your filter selection in the sidebar.")
    st.stop()

# KPI Metric Cards
total_inc = len(filtered_df)
open_inc = int((filtered_df["Status"] == "Open").sum())
prog_inc = int((filtered_df["Status"] == "In Progress").sum())
unresolved_inc = open_inc + prog_inc
resolved_inc = int((filtered_df["Status"] == "Resolved").sum())
res_rate = round((resolved_inc / total_inc) * 100, 1) if total_inc > 0 else 0.0

high_crit_count = int(filtered_df["Severity"].isin(["High", "Critical"]).sum())
high_crit_pct = round((high_crit_count / total_inc) * 100, 1) if total_inc > 0 else 0.0

resolved_hours = filtered_df.loc[filtered_df["Status"] == "Resolved", "Resolution_Hours"].dropna()
if len(resolved_hours) > 0:
    avg_hours = f"{round(resolved_hours.mean(), 1)} hrs"
    med_hours = f"Median: {round(resolved_hours.median(), 1)} hrs"
else:
    avg_hours = "N/A"
    med_hours = "No resolved cases"

k1, k2, k3, k4, k5 = st.columns(5)
with k1:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Total Incidents</div>
        <div class="kpi-value">{total_inc}</div>
        <div class="kpi-sub">Filtered Volume</div>
    </div>
    """, unsafe_allow_html=True)

with k2:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Active Backlog</div>
        <div class="kpi-value">{unresolved_inc}</div>
        <div class="kpi-sub">Open ({open_inc}) | In Prog ({prog_inc})</div>
    </div>
    """, unsafe_allow_html=True)

with k3:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Resolved Cases</div>
        <div class="kpi-value">{resolved_inc}</div>
        <div class="kpi-sub">Resolution Rate: {res_rate}%</div>
    </div>
    """, unsafe_allow_html=True)

with k4:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">High & Critical</div>
        <div class="kpi-value">{high_crit_count}</div>
        <div class="kpi-sub">{high_crit_pct}% of total volume</div>
    </div>
    """, unsafe_allow_html=True)

with k5:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Avg MTTR (Resolved)</div>
        <div class="kpi-value">{avg_hours}</div>
        <div class="kpi-sub">{med_hours}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Row 1: Time Trend & Severity Donut
r1_col1, r1_col2 = st.columns([1.6, 1.0])

with r1_col1:
    st.subheader("📈 Monthly Incident Trajectory & Containment")
    monthly_counts = filtered_df.groupby("Year_Month").size().reset_index(name="Incident_Count")
    monthly_resolved = filtered_df[filtered_df["Status"] == "Resolved"].groupby("Year_Month").size().reset_index(name="Resolved_Count")
    trend_merged = pd.merge(monthly_counts, monthly_resolved, on="Year_Month", how="left").fillna(0)

    fig_trend = go.Figure()
    fig_trend.add_trace(go.Scatter(
        x=trend_merged["Year_Month"],
        y=trend_merged["Incident_Count"],
        mode="lines+markers",
        name="Total Logged",
        line=dict(color="#1F4E78", width=3),
        marker=dict(size=8)
    ))
    fig_trend.add_trace(go.Scatter(
        x=trend_merged["Year_Month"],
        y=trend_merged["Resolved_Count"],
        mode="lines+markers",
        name="Resolved Cases",
        line=dict(color="#2CA02C", width=2, dash="dash"),
        marker=dict(size=6)
    ))
    fig_trend.update_layout(
        xaxis_title="Reporting Month",
        yaxis_title="Incident Count",
        hovermode="x unified",
        margin=dict(l=20, r=20, t=30, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig_trend, width="stretch")

with r1_col2:
    st.subheader("🎯 Severity Tier Share")
    sev_counts = filtered_df["Severity"].value_counts().reset_index()
    sev_counts.columns = ["Severity", "Count"]

    fig_sev = px.pie(
        sev_counts,
        names="Severity",
        values="Count",
        hole=0.45,
        color="Severity",
        color_discrete_map=SEVERITY_PALETTE
    )
    fig_sev.update_traces(textposition="inside", textinfo="percent+label")
    fig_sev.update_layout(
        showlegend=False,
        margin=dict(l=20, r=20, t=30, b=20)
    )
    st.plotly_chart(fig_sev, width="stretch")

# Row 2: Threat Vectors & Department Breakdown
r2_col1, r2_col2 = st.columns(2)

with r2_col1:
    st.subheader("🔍 Incidents by Attack Vector")
    type_counts = filtered_df["Incident_Type"].value_counts().reset_index()
    type_counts.columns = ["Incident_Type", "Count"]
    type_counts = type_counts.sort_values(by="Count", ascending=True)

    fig_types = px.bar(
        type_counts,
        x="Count",
        y="Incident_Type",
        orientation="h",
        text="Count",
        color="Count",
        color_continuous_scale="Blues"
    )
    fig_types.update_layout(
        xaxis_title="Number of Incidents",
        yaxis_title="",
        coloraxis_showscale=False,
        margin=dict(l=20, r=20, t=30, b=20)
    )
    st.plotly_chart(fig_types, width="stretch")

with r2_col2:
    st.subheader("🏢 Department Exposure & Urgency")
    dept_sev = filtered_df.groupby(["Department", "Severity"]).size().reset_index(name="Count")
    
    fig_dept = px.bar(
        dept_sev,
        x="Department",
        y="Count",
        color="Severity",
        color_discrete_map=SEVERITY_PALETTE,
        barmode="stack"
    )
    fig_dept.update_layout(
        xaxis_title="",
        yaxis_title="Incident Count",
        margin=dict(l=20, r=20, t=30, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig_dept, width="stretch")

# Row 3: MTTR & Analyst Methodology
st.subheader("⏱️ Mean Time to Resolve (MTTR) by Attack Vector")
resolved_subset = filtered_df[filtered_df["Status"] == "Resolved"].copy()

if resolved_subset.empty:
    st.info("No resolved incidents exist under the current filter selection to compute MTTR.")
else:
    r3_col1, r3_col2 = st.columns([1.5, 1.0])
    with r3_col1:
        res_by_type = resolved_subset.groupby(["Incident_Type", "Severity"])["Resolution_Hours"].mean().reset_index()
        fig_mttr = px.bar(
            res_by_type,
            x="Incident_Type",
            y="Resolution_Hours",
            color="Severity",
            color_discrete_map=SEVERITY_PALETTE,
            barmode="group",
            labels={"Resolution_Hours": "Avg Hours to Resolve", "Incident_Type": ""}
        )
        fig_mttr.update_layout(
            yaxis_title="Average Hours",
            margin=dict(l=20, r=20, t=30, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_mttr, width="stretch")

    with r3_col2:
        st.markdown("""
        <div style="background-color: #EFF6FF; border-left: 4px solid #3B82F6; padding: 14px; border-radius: 4px; margin-top: 10px;">
            <strong style="color: #1E40AF;">💡 Analyst Methodology Note:</strong>
            <p style="font-size: 0.9rem; color: #1E3A8A; margin-top: 8px; line-height: 1.5;">
            In SOC analytics, <strong>unresolved cases must be excluded</strong> from resolution time computations. Treating unclosed tickets as 0 hours artificially depresses resolution averages, creating a false impression of fast resolution.
            <br><br>
            Ransomware and complex data leaks exhibit longer tail resolution times due to forensic recovery and containment verification.
            </p>
        </div>
        """, unsafe_allow_html=True)
