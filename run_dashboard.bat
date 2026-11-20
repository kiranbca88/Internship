@echo off
title CYBERSHIELD - SOC Command Center
echo ====================================================================
echo   CYBERSHIELD // CYBER SECURITY INCIDENT ANALYTICS DASHBOARD
echo   Starting Streamlit SOC Command Center on http://localhost:8501 ...
echo ====================================================================

:: Free port 8501 if previously occupied by a stale process
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8501 ^| findstr LISTENING') do taskkill /f /pid %%a >nul 2>&1

start "" "http://localhost:8501"
python -m streamlit run app.py
pause
