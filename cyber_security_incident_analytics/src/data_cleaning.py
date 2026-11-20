"""
data_cleaning.py
----------------
Data cleaning and validation module for cybersecurity incident analytics.

This module validates schemas, cleans string formatting, enforces correct
data types, handles missing values methodically, and saves the cleaned dataset.

CRITICAL RULE:
Missing resolution hours for unresolved incidents (Open / In Progress)
must NEVER be replaced with zero, as that severely biases SLA and MTTR metrics.
"""

import os
import pandas as pd
import numpy as np
from typing import Dict, Any, Tuple

# Expected schema and valid categories
REQUIRED_COLUMNS = [
    "Incident_ID",
    "Incident_Date",
    "Incident_Type",
    "Severity",
    "Department",
    "Status",
    "Resolution_Hours",
    "Description"
]

VALID_INCIDENT_TYPES = {
    "Phishing",
    "Malware",
    "Ransomware",
    "Suspicious Login",
    "Data Leak",
    "Unauthorized Access"
}

VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
VALID_STATUSES = {"Open", "In Progress", "Resolved"}

def validate_schema(df: pd.DataFrame) -> None:
    """
    Validate that all required columns are present in the dataframe.

    Raises:
        ValueError: If any required column is missing.
    """
    missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Schema validation failed. Missing required columns: {missing_cols}")

def clean_incident_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Clean, validate, and standardize cybersecurity incident data.

    Steps performed:
    1. Validate required columns.
    2. Remove duplicate records.
    3. Strip whitespace and standardize string cases.
    4. Validate categories against expected domain values.
    5. Convert Incident_Date to datetime and Resolution_Hours to numeric float.
    6. Ensure unresolved incidents have NaN Resolution_Hours (never zero).
    7. Generate a comprehensive cleaning summary.

    Parameters:
        df (pd.DataFrame): Raw dataframe.

    Returns:
        Tuple[pd.DataFrame, Dict[str, Any]]: Cleaned dataframe and summary dictionary.
    """
    validate_schema(df)
    initial_row_count = len(df)
    
    # 1. Deduplication
    # Check for exact duplicate rows or repeated Incident_IDs
    df_cleaned = df.drop_duplicates(subset=["Incident_ID"]).copy()
    duplicates_removed = initial_row_count - len(df_cleaned)

    # 2. String Cleaning (trim whitespace)
    string_cols = ["Incident_Type", "Severity", "Department", "Status", "Description"]
    for col in string_cols:
        if col in df_cleaned.columns:
            df_cleaned[col] = df_cleaned[col].astype(str).str.strip()

    # 3. Category Validation
    # Identify any invalid categories
    invalid_types = df_cleaned[~df_cleaned["Incident_Type"].isin(VALID_INCIDENT_TYPES)]
    invalid_sevs = df_cleaned[~df_cleaned["Severity"].isin(VALID_SEVERITIES)]
    invalid_stats = df_cleaned[~df_cleaned["Status"].isin(VALID_STATUSES)]

    if len(invalid_types) > 0:
        raise ValueError(f"Found invalid Incident_Type entries: {invalid_types['Incident_Type'].unique()}")
    if len(invalid_sevs) > 0:
        raise ValueError(f"Found invalid Severity entries: {invalid_sevs['Severity'].unique()}")
    if len(invalid_stats) > 0:
        raise ValueError(f"Found invalid Status entries: {invalid_stats['Status'].unique()}")

    # 4. Data Type Conversions
    # Parse date strings to pandas datetime
    df_cleaned["Incident_Date"] = pd.to_datetime(df_cleaned["Incident_Date"], errors="coerce")
    if df_cleaned["Incident_Date"].isnull().any():
        raise ValueError("Detected unparseable dates in Incident_Date column.")

    # Convert Resolution_Hours to float
    df_cleaned["Resolution_Hours"] = pd.to_numeric(df_cleaned["Resolution_Hours"], errors="coerce")

    # 5. Missing Value Validation & Business Logic Rule:
    # RULE: Unresolved incidents (Open, In Progress) MUST have NaN Resolution_Hours.
    # NEVER fill with 0.0 because 0.0 implies instant resolution in zero seconds!
    unresolved_mask = df_cleaned["Status"].isin(["Open", "In Progress"])
    df_cleaned.loc[unresolved_mask, "Resolution_Hours"] = np.nan

    # For Resolved incidents, verify resolution hours exist
    resolved_mask = df_cleaned["Status"] == "Resolved"
    resolved_missing_hours = df_cleaned[resolved_mask & df_cleaned["Resolution_Hours"].isnull()]
    
    # If any resolved record has missing hours, impute using median of that severity
    if len(resolved_missing_hours) > 0:
        for sev in VALID_SEVERITIES:
            sev_median = df_cleaned[
                (df_cleaned["Severity"] == sev) & (df_cleaned["Status"] == "Resolved")
            ]["Resolution_Hours"].median()
            fill_mask = resolved_mask & df_cleaned["Resolution_Hours"].isnull() & (df_cleaned["Severity"] == sev)
            df_cleaned.loc[fill_mask, "Resolution_Hours"] = round(sev_median, 1)

    # Sort deterministically by Incident_Date
    df_cleaned = df_cleaned.sort_values(by="Incident_Date").reset_index(drop=True)

    # Recalculate masks on the sorted dataframe
    final_resolved_mask = df_cleaned["Status"] == "Resolved"
    final_unresolved_mask = df_cleaned["Status"].isin(["Open", "In Progress"])

    summary = {
        "initial_rows": initial_row_count,
        "duplicates_removed": duplicates_removed,
        "final_cleaned_rows": len(df_cleaned),
        "total_resolved": int(final_resolved_mask.sum()),
        "total_unresolved": int(final_unresolved_mask.sum()),
        "unresolved_null_hours_retained": int(df_cleaned[final_unresolved_mask]["Resolution_Hours"].isnull().sum()),
        "date_range_start": str(df_cleaned["Incident_Date"].min()),
        "date_range_end": str(df_cleaned["Incident_Date"].max()),
    }

    return df_cleaned, summary

def run_cleaning_pipeline(raw_path: str, output_path: str) -> pd.DataFrame:
    """
    Execute the end-to-end cleaning process from raw CSV to processed CSV.

    Parameters:
        raw_path (str): File path to raw incidents CSV.
        output_path (str): Destination file path for cleaned incidents CSV.

    Returns:
        pd.DataFrame: Cleaned dataframe.
    """
    if not os.path.exists(raw_path):
        raise FileNotFoundError(f"Raw data file not found at: {raw_path}")

    print(f"[INFO] Reading raw data from: {raw_path}")
    raw_df = pd.read_csv(raw_path)

    cleaned_df, summary = clean_incident_data(raw_df)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    cleaned_df.to_csv(output_path, index=False)

    print("\n--- DATA CLEANING SUMMARY REPORT ---")
    print(f"Total Raw Records Loaded   : {summary['initial_rows']}")
    print(f"Duplicate Rows Removed     : {summary['duplicates_removed']}")
    print(f"Final Cleaned Records      : {summary['final_cleaned_rows']}")
    print(f"Resolved Incidents Count   : {summary['total_resolved']}")
    print(f"Unresolved Incidents Count : {summary['total_unresolved']}")
    print(f"Missing Hours Preserved    : {summary['unresolved_null_hours_retained']} (correctly maintained as NaN)")
    print(f"Date Span Covered          : {summary['date_range_start']} to {summary['date_range_end']}")
    print(f"[SAVED] Cleaned dataset stored at: {output_path}\n")

    return cleaned_df

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    
    raw_csv = os.path.join(project_root, "data", "raw", "incidents_sample.csv")
    cleaned_csv = os.path.join(project_root, "data", "processed", "incidents_cleaned.csv")
    
    run_cleaning_pipeline(raw_csv, cleaned_csv)
