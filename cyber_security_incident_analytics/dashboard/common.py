"""
common.py
---------
Shared utilities, data loader, CSS styles, and palettes for multi-page dashboard.
"""

import os
import sys
import pandas as pd
import streamlit as st

def get_project_root() -> str:
    """Return the absolute path to the project root directory."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

@st.cache_data
def load_data() -> pd.DataFrame:
    """Load cleaned cybersecurity incident records."""
    project_root = get_project_root()
    data_path = os.path.join(project_root, "data", "processed", "incidents_cleaned.csv")
    
    if not os.path.exists(data_path):
        return None

    df = pd.read_csv(data_path)
    df["Incident_Date"] = pd.to_datetime(df["Incident_Date"])
    df["Date_Only"] = df["Incident_Date"].dt.date
    df["Year_Month"] = df["Incident_Date"].dt.to_period("M").astype(str)
    return df

def apply_custom_css():
    """Inject polished corporate styling."""
    st.markdown("""
    <style>
        .main-header {
            font-size: 2.1rem;
            font-weight: 700;
            color: #1F4E78;
            margin-bottom: 0.2rem;
        }
        .sub-header {
            font-size: 1.0rem;
            color: #555555;
            margin-bottom: 1.2rem;
        }
        .kpi-card {
            background-color: #F8FAFC;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            padding: 14px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        .kpi-title {
            font-size: 0.8rem;
            font-weight: 600;
            color: #64748B;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .kpi-value {
            font-size: 1.85rem;
            font-weight: 700;
            color: #1E293B;
            margin: 4px 0;
        }
        .kpi-sub {
            font-size: 0.78rem;
            color: #0EA5E9;
        }
        .badge-critical {
            background-color: #FEE2E2;
            color: #991B1B;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
        }
        .badge-high {
            background-color: #FFEDD5;
            color: #9A3412;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
        }
        .badge-medium {
            background-color: #E0F2FE;
            color: #0369A1;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
        }
        .badge-low {
            background-color: #DCFCE7;
            color: #166534;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
        }
    </style>
    """, unsafe_allow_html=True)

SEVERITY_PALETTE = {
    "Critical": "#D9534F",
    "High": "#F0AD4E",
    "Medium": "#5BC0DE",
    "Low": "#5CB85C"
}

STATUS_PALETTE = {
    "Resolved": "#22C55E",
    "In Progress": "#EAB308",
    "Open": "#EF4444"
}

def render_sidebar_filters(df_raw: pd.DataFrame) -> pd.DataFrame:
    """Render interactive sidebar filter controls and return filtered DataFrame."""
    st.sidebar.markdown("### 🎛️ Filter Controls")
    
    min_date = df_raw["Date_Only"].min()
    max_date = df_raw["Date_Only"].max()
    
    date_range = st.sidebar.date_input(
        "Incident Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )
    
    all_severities = ["Critical", "High", "Medium", "Low"]
    selected_severities = st.sidebar.multiselect(
        "Severity Tier",
        options=all_severities,
        default=all_severities
    )
    
    all_types = sorted(df_raw["Incident_Type"].unique())
    selected_types = st.sidebar.multiselect(
        "Attack Vector / Type",
        options=all_types,
        default=all_types
    )
    
    all_depts = sorted(df_raw["Department"].unique())
    selected_depts = st.sidebar.multiselect(
        "Department",
        options=all_depts,
        default=all_depts
    )
    
    all_statuses = ["Resolved", "In Progress", "Open"]
    selected_statuses = st.sidebar.multiselect(
        "Resolution Status",
        options=all_statuses,
        default=all_statuses
    )

    st.sidebar.markdown("---")
    st.sidebar.caption("🛡️ **SOC Intelligence Portal**")
    st.sidebar.caption("BCA Data Analyst Portfolio Project • Synthetic Records (Seed 42)")

    if isinstance(date_range, (tuple, list)) and len(date_range) == 2:
        start_filter, end_filter = date_range
    else:
        start_filter, end_filter = min_date, max_date

    filtered_df = df_raw[
        (df_raw["Date_Only"] >= start_filter) &
        (df_raw["Date_Only"] <= end_filter) &
        (df_raw["Severity"].isin(selected_severities)) &
        (df_raw["Incident_Type"].isin(selected_types)) &
        (df_raw["Department"].isin(selected_depts)) &
        (df_raw["Status"].isin(selected_statuses))
    ].copy()

    return filtered_df
