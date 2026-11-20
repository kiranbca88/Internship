"""
generate_5_years.py
-------------------
Generates 7,000 realistic synthetic cybersecurity incident records across 5 complete
years (2021-2025) for CYBERSHIELD SOC Command Center analytics and machine learning.

DISCLAIMER: All data is completely synthetic and generated for educational and portfolio purposes.
"""

import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

def generate_5_year_dataset(num_records: int = 7000, seed: int = 42) -> pd.DataFrame:
    random.seed(seed)
    np.random.seed(seed)

    attack_types = [
        "Phishing", "Ransomware", "Malware", "DDoS", "SQL Injection",
        "Brute-Force", "Insider Threat", "Data Breach", "Spoofing", "Man-in-the-Middle"
    ]
    attack_weights = [0.22, 0.12, 0.15, 0.09, 0.08, 0.11, 0.06, 0.07, 0.05, 0.05]

    severities = ["Low", "Medium", "High", "Critical"]
    severity_weights = [0.25, 0.38, 0.24, 0.13]

    statuses = ["Resolved", "In Progress", "Open", "Under Investigation"]
    status_weights = [0.72, 0.13, 0.09, 0.06]

    departments = [
        "IT", "Finance", "HR", "Operations", "Sales",
        "Marketing", "Legal", "Engineering", "Executive", "R&D"
    ]

    locations = [
        "New York", "London", "Singapore", "Tokyo", "Frankfurt",
        "Sydney", "Toronto", "Bangalore", "São Paulo", "Dubai"
    ]

    affected_assets = [
        "Domain Controller", "Database Server", "Web Server", "Employee Workstation",
        "Cloud Storage / S3", "Payment Gateway", "VPN Concentrator", "Email Server",
        "SCADA / IoT", "CI/CD Pipeline"
    ]

    threat_actors = [
        "APT29 'Cozy Bear'", "Lazarus Group", "FIN7", "LockBit Gang",
        "Anonymous Collective", "Insider Rogue", "Script Kiddies",
        "DarkSide", "RedAlpha", "Volt Typhoon"
    ]

    attack_vectors = [
        "Compromised Credentials", "Malicious Email Link", "Zero-Day Exploit",
        "Misconfigured S3 Bucket", "Unpatched Software", "Remote Desktop Protocol",
        "Supply Chain Dependency", "Weak Wi-Fi Encryption"
    ]

    root_causes = [
        "Weak Passwords", "Social Engineering", "Missing Security Patch",
        "Third-Party Vendor Vulnerability", "Misconfiguration",
        "Zero-Day Vulnerability", "Lack of Employee Training"
    ]

    mfa_statuses = ["Enabled", "Disabled", "Bypassed"]
    mfa_weights = [0.55, 0.33, 0.12]

    start_date = datetime(2021, 1, 1, 0, 0, 0)
    end_date = datetime(2025, 12, 31, 23, 59, 59)
    total_seconds = int((end_date - start_date).total_seconds())

    # Generate timestamps distributed across 5 years with slight growth trend
    # Simulates enterprise telemetry scaling from 2021 to 2025
    timestamps = []
    for _ in range(num_records):
        # Weighted slightly towards more recent years (2024-2025)
        u = random.betavariate(1.2, 1.0)
        sec_offset = int(u * total_seconds)
        dt = start_date + timedelta(seconds=sec_offset)
        timestamps.append(dt)

    timestamps.sort()

    records = []
    month_names = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    ]

    for idx, dt in enumerate(timestamps, start=1):
        year = dt.year
        month = month_names[dt.month - 1]
        quarter = f"Q{(dt.month - 1) // 3 + 1}"
        inc_id = f"CS-{year}-{idx:05d}"

        attack = random.choices(attack_types, weights=attack_weights)[0]
        
        # Correlate severity with attack type
        if attack in ["Ransomware", "Data Breach", "Insider Threat"]:
            severity = random.choices(severities, weights=[0.05, 0.20, 0.45, 0.30])[0]
        elif attack in ["Phishing", "Brute-Force", "Spoofing"]:
            severity = random.choices(severities, weights=[0.40, 0.40, 0.15, 0.05])[0]
        elif attack == "SQL Injection":
            severity = random.choices(severities, weights=[0.10, 0.35, 0.35, 0.20])[0]
        else:
            severity = random.choices(severities, weights=severity_weights)[0]

        status = random.choices(statuses, weights=status_weights)[0]
        department = random.choice(departments)
        location = random.choice(locations)

        # Asset correlation
        if attack == "SQL Injection":
            asset = "Database Server"
        elif attack == "DDoS":
            asset = random.choice(["Web Server", "Payment Gateway", "VPN Concentrator"])
        elif attack == "Phishing":
            asset = random.choice(["Email Server", "Employee Workstation"])
        elif attack == "Ransomware":
            asset = random.choice(["Domain Controller", "Database Server", "Employee Workstation", "Cloud Storage / S3"])
        else:
            asset = random.choice(affected_assets)

        threat_actor = random.choice(threat_actors)
        
        # Vector correlation
        if attack == "Phishing":
            vector = random.choice(["Malicious Email Link", "Compromised Credentials"])
            root_cause = random.choice(["Social Engineering", "Lack of Employee Training"])
        elif attack == "Brute-Force":
            vector = random.choice(["Remote Desktop Protocol", "Compromised Credentials"])
            root_cause = "Weak Passwords"
        elif attack == "Ransomware":
            vector = random.choice(["Unpatched Software", "Remote Desktop Protocol", "Malicious Email Link"])
            root_cause = random.choice(["Missing Security Patch", "Third-Party Vendor Vulnerability"])
        elif attack == "Data Breach":
            vector = random.choice(["Misconfigured S3 Bucket", "Compromised Credentials", "Supply Chain Dependency"])
            root_cause = random.choice(["Misconfiguration", "Third-Party Vendor Vulnerability"])
        else:
            vector = random.choice(attack_vectors)
            root_cause = random.choice(root_causes)

        mfa = random.choices(mfa_statuses, weights=mfa_weights)[0]

        # Data Exfiltration correlation
        if attack in ["Data Breach", "Ransomware", "SQL Injection", "Insider Threat"]:
            exfiltration = random.choices(["Yes", "No"], weights=[0.70, 0.30])[0]
        else:
            exfiltration = random.choices(["Yes", "No"], weights=[0.10, 0.90])[0]

        # Records Affected calculation
        if exfiltration == "Yes":
            if attack == "Data Breach":
                records_affected = int(np.random.lognormal(mean=9.5, sigma=1.2))  # thousands to 100k+
            elif attack == "SQL Injection":
                records_affected = int(np.random.lognormal(mean=8.5, sigma=1.0))
            elif attack == "Ransomware":
                records_affected = int(np.random.lognormal(mean=7.5, sigma=1.1))
            else:
                records_affected = int(np.random.lognormal(mean=6.0, sigma=1.0))
            records_affected = max(10, min(records_affected, 750000))
        else:
            records_affected = 0

        # Response Time (hours): Time to detect / initial SOC response
        # Critical incidents detected faster through automated SOC SIEM alerts
        if severity == "Critical":
            response_time = round(float(np.random.gamma(shape=1.5, scale=0.8)), 2)  # ~1.2 hrs
        elif severity == "High":
            response_time = round(float(np.random.gamma(shape=2.0, scale=1.2)), 2)  # ~2.4 hrs
        elif severity == "Medium":
            response_time = round(float(np.random.gamma(shape=2.5, scale=2.0)), 2)  # ~5.0 hrs
        else:  # Low
            response_time = round(float(np.random.gamma(shape=3.0, scale=3.0)), 2)  # ~9.0 hrs
        response_time = max(0.1, min(response_time, 48.0))

        # Resolution Time (hours): Only for Resolved tickets!
        if status == "Resolved":
            if severity == "Critical":
                res_hours = round(float(np.random.gamma(shape=4.0, scale=7.5)), 1)  # ~30 hrs
            elif severity == "High":
                res_hours = round(float(np.random.gamma(shape=3.5, scale=4.8)), 1)  # ~17 hrs
            elif severity == "Medium":
                res_hours = round(float(np.random.gamma(shape=3.0, scale=3.0)), 1)  # ~9 hrs
            else:
                res_hours = round(float(np.random.gamma(shape=2.0, scale=2.0)), 1)  # ~4 hrs
            if attack == "Ransomware":
                res_hours *= 1.6  # Ransomware recovery takes longer
            resolution_time = max(0.5, min(round(res_hours, 1), 240.0))
        else:
            resolution_time = np.nan  # CRITICAL: Missing for unclosed tickets

        # Financial Loss ($): Base costs + records impacted penalty + severity multiplier
        sev_multiplier = {"Critical": 4.5, "High": 2.5, "Medium": 1.2, "Low": 0.4}[severity]
        base_loss = np.random.uniform(5000, 35000) * sev_multiplier
        
        # Stolen records add GDPR/regulatory compliance & identity theft protection costs ($80 - $220/record)
        record_cost = records_affected * random.uniform(85.0, 195.0) if exfiltration == "Yes" else 0.0

        ransom_cost = np.random.uniform(150000, 1200000) if (attack == "Ransomware" and severity in ["Critical", "High"]) else 0.0

        total_loss = round(base_loss + record_cost + ransom_cost, 2)
        total_loss = max(1200.0, min(total_loss, 4500000.0))

        records.append({
            "Incident_ID": inc_id,
            "Date": dt.strftime("%Y-%m-%d %H:%M:%S"),
            "Year": year,
            "Month": month,
            "Quarter": quarter,
            "Attack_Type": attack,
            "Severity": severity,
            "Status": status,
            "Department": department,
            "Location": location,
            "Affected_Asset": asset,
            "Threat_Actor": threat_actor,
            "Attack_Vector": vector,
            "Root_Cause": root_cause,
            "Response_Time": response_time,
            "Resolution_Time": resolution_time,
            "Records_Affected": records_affected,
            "Financial_Loss": total_loss,
            "Data_Exfiltration": exfiltration,
            "Multi_Factor_Authentication": mfa
        })

    df = pd.DataFrame(records)
    return df

def save_dataset(df: pd.DataFrame, file_paths: list):
    for path in file_paths:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        df.to_csv(path, index=False)
        print(f"[SUCCESS] Saved dataset ({len(df):,} records) to: {path}")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    proj_root = os.path.dirname(script_dir)
    workspace_root = os.path.dirname(proj_root)

    print("[INFO] Generating 7,000 synthetic cybersecurity incidents over 2021-2025...")
    df_5y = generate_5_year_dataset(num_records=7000, seed=42)

    target_paths = [
        os.path.join(proj_root, "cyber_incidents_5_years.csv"),
        os.path.join(proj_root, "data", "cyber_incidents_5_years.csv"),
        os.path.join(workspace_root, "cyber_incidents_5_years.csv")
    ]
    save_dataset(df_5y, target_paths)
    print("\nDataset Generation Complete!")
    print(f"Total Rows: {len(df_5y):,}")
    print(f"Years: {sorted(df_5y['Year'].unique())}")
    print(f"Attack Types: {sorted(df_5y['Attack_Type'].unique())}")
    print(f"Total Financial Impact: ${df_5y['Financial_Loss'].sum():,.2f}")

