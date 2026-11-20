# 🛡️ CYBERSHIELD – Cyber Security Incident Analytics
### Enterprise Security Operations Center (SOC) Command Center | 2021–2025
*Bachelor of Computer Application (BCA) Final-Year Capstone Project*  
*Course Code: CA5P3 (Internship) — Bengaluru North University*

---

## 👨‍🎓 Candidate & Institutional Details
- **Candidate Name:** **Kiran S**
- **Registration Number:** **U19XF24S0049**
- **Degree:** Bachelor of Computer Application (BCA), Fifth/Sixth Semester
- **Institution:** **MVJ DEGREE COLLEGE**, Near ITPB / ITPL, Channasandra, Bengaluru – 560067
- **University:** **Bengaluru North University**
- **Internal Faculty Guide:** **Prof. Navya V**, Assistant Professor, Department of Computer Science
- **Host Organization:** **Trishana Technologies Pvt. Ltd., Bengaluru**
- **External Industry Mentors:** **Ms. Sahana** (Technical Trainer) & **Mr. Ayyanar G** (Manager)
- **Batch / Academic Period:** 2024 – 2027

---

## 📌 Project Overview
**CYBERSHIELD** is an enterprise-grade Security Operations Center (SOC) incident intelligence and triage platform. Analyzing a comprehensive **5-year longitudinal enterprise telemetry dataset (7,000 incident events, 2021–2025)**, the platform delivers real-time situational awareness, multi-dimensional risk visual analytics, and predictive machine learning triage to eliminate Tier-1 analyst cognitive fatigue.

### Core Capabilities:
1. **Interactive 9-View Web Command Center:** Built with Streamlit and Plotly, delivering 18 high-performance data visualizations.
2. **Supervised Machine Learning Triage:** Scikit-learn Random Forest Classifier (150 estimators) achieving **88.43% test accuracy** for automated alert severity prioritization (Low, Medium, High, Critical).
3. **Principled Data Governance:** Enforces strict null-value retention for unresolved tickets, eliminating the pervasive industry problem of artificial Mean Time to Resolve (MTTR) deflation.
4. **Actionable Incident Containment Playbooks:** Operational workflows aligned with NIST SP 800-61 and ISO/IEC 27001 standards.
5. **Zero-Dependency Standalone Exporter:** Automated client-side HTML dashboard generation (`cybershield_soc_dashboard.html`) powered by Plotly.js for offline executive reporting.

---

## 🗂️ Project Architecture & Directory Structure
```text
Internship/
├── app.py                             # Master Streamlit SOC Command Center Dashboard
├── requirements.txt                   # Production Python Dependencies
├── README.md                          # Full Project Documentation & Viva Reference Guide
├── cyber_incidents_5_years.csv        # 5-Year Enterprise Telemetry Dataset (7,000 records)
├── cybershield_soc_dashboard.html     # Standalone Zero-Dependency Executive HTML Dashboard
├── export_html.py                     # Offline Dashboard Compilation Script
├── run.py                             # Master Python Execution Runner
├── run_dashboard.bat                  # 1-Click Windows Batch Launcher
├── .gitignore                         # Git Source Control Filter Rules
│
├── modules/                           # Reusable Core Analytical Engine
│   ├── __init__.py                    # Package Initializer
│   ├── data_processing.py             # Telemetry cleaning, missing-value governance & KPI math
│   ├── analytics.py                   # Plotly interactive chart figure generators
│   └── ml_model.py                    # Scikit-learn Random Forest classifier & live inference
│
├── outputs/                           # Serialized Machine Learning Models
│   ├── severity_classifier.joblib     # Production Random Forest Model Pipeline
│   └── severity_classifier_v2.joblib  # Extended Trained Model Artifact
│
├── assets/                            # Design & Typography Assets
│   ├── styles.css                     # Custom SOC Command Center Dark Palette CSS
│   ├── bnu_logo.png                   # Bengaluru North University Insignia
│   └── mvj_logo.png                   # MVJ Degree College Insignia
│
└── cyber_security_incident_analytics/ # Subproject Modular Package
    ├── dashboard/                     # Multi-Page Streamlit Views
    ├── data/                          # Raw & Processed Telemetry Subsets
    ├── sql/                           # Relational Database Schemas & Analytical SQL Queries
    ├── src/                           # Synthetic Telemetry Generation & Training Scripts
    └── tests/                         # PyTest Unit Verification Suites
```

---

## 🚀 Quick Start & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/kiranbca88/Internship.git
cd Internship
```

### 2. Create and Activate a Python Virtual Environment
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the CYBERSHIELD SOC Web Command Center
```bash
streamlit run app.py
```
*Or double-click `run_dashboard.bat` on Windows.*

The dashboard will open automatically in your browser at `http://localhost:8501`.

---

## 📊 Empirical Telemetry Dataset Summary (2021–2025)
- **Total Validated Records:** 7,000 security incidents
- **Longitudinal Scope:** 60 consecutive months (January 1, 2021 – December 31, 2025)
- **Cumulative Direct Losses:** **$2,163,006,994.47 USD** (Mean: $309,001.00 per incident)
- **Top Threat Vectors:**
  - *Phishing:* 1,546 incidents (22.09%) — Primary initial access vector
  - *Malware:* 1,032 incidents (14.74%)
  - *Ransomware:* 830 incidents (11.86%) — Highest economic loss ($485,750 mean damage)
- **Multi-Factor Authentication (MFA) Defense Efficacy:**
  - MFA Enabled: **18.39% exfiltration rate** (42% lower financial damage)
  - MFA Disabled / Bypassed: **68.70% – 74.21% exfiltration rate**
- **Overall Mean Time to Resolve (MTTR):** 14.32 hours across 5,090 resolved tickets

---

## 🤖 Machine Learning Model Performance
- **Algorithm:** Scikit-learn `RandomForestClassifier` (150 estimators, max depth 15, balanced class weights)
- **Features Used:** `Attack_Type`, `Attack_Vector`, `Root_Cause`, `Affected_Asset`, `Department`, `Multi_Factor_Auth`
- **Train/Test Split:** 80/20 Stratified Partition (5,600 training samples / 1,400 test samples)
- **Overall Test Accuracy:** **88.43%**
- **Macro F1-Score:** **0.883**
- **Critical Severity Recall:** **0.86** (ensuring critical intrusions are never missed)

---

## 📜 Compliance & Academic Alignment
Developed to fulfill Course Code **CA5P3: Internship** (02 Credits, 90 Contact Hours) under the Bachelor of Computer Application (BCA) curriculum of **Bengaluru North University**, aligned with:
- **NIST SP 800-61 Rev. 2** (Computer Security Incident Handling Guide)
- **ISO/IEC 27001:2022** (Information Security Management Systems)
- **MITRE ATT&CK® Enterprise Matrix**
- **CERT-In** Cybersecurity Incident Reporting Directives
