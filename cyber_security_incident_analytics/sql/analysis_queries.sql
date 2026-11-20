-- ====================================================================
-- Cyber Security Incident Analytics - Analytical SQL Queries
-- Demonstrates SQL skills: Aggregations, GROUP BY, CASE statements,
-- Date formatting, Window functions, and Conditional filtering.
-- ====================================================================

-- --------------------------------------------------------------------
-- QUERY 1: Overall KPI Summary (Total, Statuses, and High/Critical Share)
-- --------------------------------------------------------------------
SELECT 
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN Status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_incidents,
    SUM(CASE WHEN Status = 'Open' THEN 1 ELSE 0 END) AS open_incidents,
    SUM(CASE WHEN Status = 'In Progress' THEN 1 ELSE 0 END) AS in_progress_incidents,
    ROUND(SUM(CASE WHEN Status = 'Resolved' THEN 1.0 ELSE 0.0 END) * 100.0 / COUNT(*), 1) AS resolution_rate_pct,
    SUM(CASE WHEN Severity IN ('High', 'Critical') THEN 1 ELSE 0 END) AS high_critical_count,
    ROUND(SUM(CASE WHEN Severity IN ('High', 'Critical') THEN 1.0 ELSE 0.0 END) * 100.0 / COUNT(*), 1) AS high_critical_pct,
    -- CRITICAL: Only average resolution hours for resolved cases
    ROUND(AVG(CASE WHEN Status = 'Resolved' THEN Resolution_Hours END), 1) AS overall_avg_resolution_hours
FROM cyber_incidents;

-- --------------------------------------------------------------------
-- QUERY 2: Severity Distribution Breakdown
-- --------------------------------------------------------------------
SELECT 
    Severity,
    COUNT(*) AS incident_count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM cyber_incidents), 1) AS percentage_of_total,
    ROUND(AVG(CASE WHEN Status = 'Resolved' THEN Resolution_Hours END), 1) AS avg_resolution_hours_resolved
FROM cyber_incidents
GROUP BY Severity
ORDER BY 
    CASE Severity 
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
    END;

-- --------------------------------------------------------------------
-- QUERY 3: Threat Types Breakdown & Average Resolution Time
-- --------------------------------------------------------------------
SELECT 
    Incident_Type,
    COUNT(*) AS total_incidents,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM cyber_incidents), 1) AS share_pct,
    SUM(CASE WHEN Status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_count,
    ROUND(AVG(CASE WHEN Status = 'Resolved' THEN Resolution_Hours END), 1) AS avg_resolution_hours
FROM cyber_incidents
GROUP BY Incident_Type
ORDER BY total_incidents DESC;

-- --------------------------------------------------------------------
-- QUERY 4: Department Comparison & Risk Exposure
-- --------------------------------------------------------------------
SELECT 
    Department,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN Severity IN ('High', 'Critical') THEN 1 ELSE 0 END) AS high_or_critical_incidents,
    SUM(CASE WHEN Status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_count,
    ROUND(AVG(CASE WHEN Status = 'Resolved' THEN Resolution_Hours END), 1) AS avg_resolution_hours
FROM cyber_incidents
GROUP BY Department
ORDER BY total_incidents DESC;

-- --------------------------------------------------------------------
-- QUERY 5: Monthly Incident Volume & Resolution Trends
-- --------------------------------------------------------------------
SELECT 
    SUBSTR(Incident_Date, 1, 7) AS year_month,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN Status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_incidents,
    SUM(CASE WHEN Status != 'Resolved' THEN 1 ELSE 0 END) AS open_or_in_progress,
    ROUND(AVG(CASE WHEN Status = 'Resolved' THEN Resolution_Hours END), 1) AS avg_resolution_hours
FROM cyber_incidents
GROUP BY SUBSTR(Incident_Date, 1, 7)
ORDER BY year_month ASC;

-- --------------------------------------------------------------------
-- QUERY 6: Resolution Hours Deep Dive (Min, Max, Avg by Severity)
-- Note: SQLite does not have a native MEDIAN() function, so we compute
-- MIN, MAX, and AVG on resolved rows.
-- --------------------------------------------------------------------
SELECT 
    Severity,
    COUNT(Resolution_Hours) AS resolved_sample_size,
    ROUND(MIN(Resolution_Hours), 1) AS min_resolution_hours,
    ROUND(AVG(Resolution_Hours), 1) AS avg_resolution_hours,
    ROUND(MAX(Resolution_Hours), 1) AS max_resolution_hours
FROM cyber_incidents
WHERE Status = 'Resolved'
GROUP BY Severity
ORDER BY 
    CASE Severity 
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
    END;

-- --------------------------------------------------------------------
-- QUERY 7: Active Incident Triage Queue (Unresolved high/critical tickets)
-- --------------------------------------------------------------------
SELECT 
    Incident_ID,
    Incident_Date,
    Incident_Type,
    Severity,
    Department,
    Status,
    Description
FROM cyber_incidents
WHERE Status IN ('Open', 'In Progress')
  AND Severity IN ('High', 'Critical')
ORDER BY Incident_Date ASC;

