"""
test_analysis.py
----------------
Unit tests for Cyber Security Incident Analytics using pytest.
Validates KPI formulas, SLA calculation rules, missing value guards,
empty dataset edge cases, and data cleaning integrity.
"""

import os
import sys

# Ensure project root is on sys.path
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TESTS_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
import numpy as np
import pandas as pd
from datetime import datetime

try:
    from src.analysis import (
        calculate_kpis,
        get_severity_distribution,
        get_incident_types_summary,
        get_department_summary,
        get_monthly_trend,
        get_resolution_by_severity
    )
    from src.data_cleaning import clean_incident_data, validate_schema
except ImportError:
    from analysis import (
        calculate_kpis,
        get_severity_distribution,
        get_incident_types_summary,
        get_department_summary,
        get_monthly_trend,
        get_resolution_by_severity
    )
    from data_cleaning import clean_incident_data, validate_schema

@pytest.fixture
def sample_incident_df():
    """Provides a controlled synthetic dataset of 6 incidents with known metrics."""
    data = [
        {
            "Incident_ID": "INC-TEST-0001",
            "Incident_Date": "2024-01-15 08:30:00",
            "Incident_Type": "Phishing",
            "Severity": "Low",
            "Department": "Finance",
            "Status": "Resolved",
            "Resolution_Hours": 6.0,
            "Description": "Test phishing resolved"
        },
        {
            "Incident_ID": "INC-TEST-0002",
            "Incident_Date": "2024-01-20 14:00:00",
            "Incident_Type": "Malware",
            "Severity": "High",
            "Department": "IT",
            "Status": "Resolved",
            "Resolution_Hours": 18.0,
            "Description": "Test malware resolved"
        },
        {
            "Incident_ID": "INC-TEST-0003",
            "Incident_Date": "2024-02-05 11:15:00",
            "Incident_Type": "Ransomware",
            "Severity": "Critical",
            "Department": "Operations",
            "Status": "Resolved",
            "Resolution_Hours": 36.0,
            "Description": "Test ransomware resolved"
        },
        {
            "Incident_ID": "INC-TEST-0004",
            "Incident_Date": "2024-02-18 16:45:00",
            "Incident_Type": "Suspicious Login",
            "Severity": "Medium",
            "Department": "HR",
            "Status": "Open",
            "Resolution_Hours": np.nan,  # Unresolved incident must be NaN
            "Description": "Test open suspicious login"
        },
        {
            "Incident_ID": "INC-TEST-0005",
            "Incident_Date": "2024-03-01 09:00:00",
            "Incident_Type": "Data Leak",
            "Severity": "High",
            "Department": "Legal",
            "Status": "In Progress",
            "Resolution_Hours": np.nan,  # In Progress incident must be NaN
            "Description": "Test in-progress data leak"
        },
        {
            "Incident_ID": "INC-TEST-0006",
            "Incident_Date": "2024-03-12 10:20:00",
            "Incident_Type": "Unauthorized Access",
            "Severity": "Critical",
            "Department": "Engineering",
            "Status": "Open",
            "Resolution_Hours": np.nan,  # Open incident must be NaN
            "Description": "Test open unauthorized access"
        }
    ]
    df = pd.DataFrame(data)
    df["Incident_Date"] = pd.to_datetime(df["Incident_Date"])
    return df

def test_kpi_calculations_normal(sample_incident_df):
    """Verify core KPI calculations against deterministic values."""
    kpis = calculate_kpis(sample_incident_df)

    assert kpis["total_incidents"] == 6
    assert kpis["resolved_incidents"] == 3
    assert kpis["open_incidents"] == 2
    assert kpis["in_progress_incidents"] == 1
    assert kpis["unresolved_incidents"] == 3
    assert kpis["resolution_rate_pct"] == 50.0  # 3 out of 6

    # High and Critical count: INC-0002 (High), INC-0003 (Critical), INC-0005 (High), INC-0006 (Critical) = 4
    assert kpis["critical_incidents"] == 2
    assert kpis["high_incidents"] == 2
    assert kpis["high_critical_incidents"] == 4
    assert kpis["high_critical_pct"] == round((4 / 6) * 100, 1)

    # Resolution hours calculation: strictly resolved rows [6.0, 18.0, 36.0]
    # Mean: (6 + 18 + 36) / 3 = 20.0
    # Median: 18.0
    assert kpis["avg_resolution_hours"] == 20.0
    assert kpis["median_resolution_hours"] == 18.0

def test_unresolved_incidents_never_counted_as_zero():
    """
    CRITICAL TEST: Ensure missing resolution hours for open/in-progress tickets
    are not imputed as 0.0, which would falsely deflate resolution times.
    """
    df = pd.DataFrame([
        {
            "Incident_ID": "INC-01",
            "Incident_Date": pd.to_datetime("2024-01-01"),
            "Incident_Type": "Phishing",
            "Severity": "Low",
            "Department": "IT",
            "Status": "Resolved",
            "Resolution_Hours": 10.0,
            "Description": "Resolved case"
        },
        {
            "Incident_ID": "INC-02",
            "Incident_Date": pd.to_datetime("2024-01-02"),
            "Incident_Type": "Phishing",
            "Severity": "Low",
            "Department": "IT",
            "Status": "Open",
            "Resolution_Hours": np.nan,  # Unresolved
            "Description": "Open case"
        }
    ])

    kpis = calculate_kpis(df)
    # Average must be 10.0 (not (10 + 0) / 2 = 5.0!)
    assert kpis["avg_resolution_hours"] == 10.0
    assert kpis["median_resolution_hours"] == 10.0

def test_empty_dataset_handling():
    """Verify analytics functions handle empty DataFrames gracefully without throwing exceptions."""
    empty_df = pd.DataFrame(columns=[
        "Incident_ID", "Incident_Date", "Incident_Type", "Severity",
        "Department", "Status", "Resolution_Hours", "Description"
    ])

    kpis = calculate_kpis(empty_df)
    assert kpis["total_incidents"] == 0
    assert kpis["avg_resolution_hours"] is None
    assert kpis["high_critical_pct"] == 0.0

    sev_df = get_severity_distribution(empty_df)
    assert sev_df.empty or len(sev_df.columns) == 3

    types_df = get_incident_types_summary(empty_df)
    assert types_df.empty

    dept_df = get_department_summary(empty_df)
    assert dept_df.empty

    trend_df = get_monthly_trend(empty_df)
    assert trend_df.empty

    res_df = get_resolution_by_severity(empty_df)
    assert res_df.empty

def test_severity_distribution(sample_incident_df):
    """Verify severity aggregation logic and percentages."""
    dist = get_severity_distribution(sample_incident_df)
    assert len(dist) == 4  # Critical, High, Medium, Low
    
    # Sum of counts must equal total incidents
    assert dist["Count"].sum() == 6
    # Sum of percentages must equal 100% (within floating point rounding)
    assert pytest.approx(dist["Percentage"].sum(), 0.5) == 100.0

def test_data_cleaning_pipeline():
    """Test data cleaning functionality: whitespace stripping, deduplication, schema validation."""
    raw_sample = pd.DataFrame([
        {
            "Incident_ID": "INC-01",
            "Incident_Date": "2024-01-01 10:00:00",
            "Incident_Type": "Phishing",
            "Severity": "Low",
            "Department": " Finance  ",  # Needs trimming
            "Status": "Resolved",
            "Resolution_Hours": "4.5",    # Needs float conversion
            "Description": "Test description"
        },
        {
            "Incident_ID": "INC-01",     # Duplicate ID
            "Incident_Date": "2024-01-01 10:00:00",
            "Incident_Type": "Phishing",
            "Severity": "Low",
            "Department": "Finance",
            "Status": "Resolved",
            "Resolution_Hours": 4.5,
            "Description": "Duplicate row"
        },
        {
            "Incident_ID": "INC-02",
            "Incident_Date": "2024-01-02 12:00:00",
            "Incident_Type": "Malware",
            "Severity": "Critical",
            "Department": "IT",
            "Status": "Open",
            "Resolution_Hours": 0.0,     # Erroneous non-null on open; must be converted to NaN
            "Description": "Open incident"
        }
    ])

    cleaned, summary = clean_incident_data(raw_sample)

    assert summary["initial_rows"] == 3
    assert summary["duplicates_removed"] == 1
    assert summary["final_cleaned_rows"] == 2
    assert cleaned.loc[cleaned["Incident_ID"] == "INC-01", "Department"].values[0] == "Finance"
    assert np.isnan(cleaned.loc[cleaned["Incident_ID"] == "INC-02", "Resolution_Hours"].values[0])

def test_schema_validation_error():
    """Ensure missing columns raise ValueError."""
    bad_df = pd.DataFrame({"Incident_ID": ["INC-01"], "Status": ["Open"]})
    with pytest.raises(ValueError, match="Schema validation failed"):
        validate_schema(bad_df)
