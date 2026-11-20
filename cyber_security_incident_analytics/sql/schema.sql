-- ====================================================================
-- Cyber Security Incident Analytics - Database Schema (SQLite compatible)
-- Portfolio project demonstrating SQL Data Definition (DDL) and constraints
-- ====================================================================

DROP TABLE IF EXISTS cyber_incidents;

CREATE TABLE cyber_incidents (
    Incident_ID VARCHAR(20) PRIMARY KEY,
    Incident_Date TEXT NOT NULL,
    Incident_Type TEXT NOT NULL CHECK (Incident_Type IN (
        'Phishing',
        'Malware',
        'Ransomware',
        'Suspicious Login',
        'Data Leak',
        'Unauthorized Access'
    )),
    Severity TEXT NOT NULL CHECK (Severity IN ('Low', 'Medium', 'High', 'Critical')),
    Department TEXT NOT NULL,
    Status TEXT NOT NULL CHECK (Status IN ('Open', 'In Progress', 'Resolved')),
    Resolution_Hours REAL,  -- NULL for Open or In Progress incidents; NEVER 0 for unresolved
    Description TEXT NOT NULL
);

-- Indexing for high-performance filtering and aggregation queries
CREATE INDEX idx_incidents_date ON cyber_incidents(Incident_Date);
CREATE INDEX idx_incidents_status ON cyber_incidents(Status);
CREATE INDEX idx_incidents_severity ON cyber_incidents(Severity);
CREATE INDEX idx_incidents_type ON cyber_incidents(Incident_Type);
CREATE INDEX idx_incidents_dept ON cyber_incidents(Department);

