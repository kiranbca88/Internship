@echo off
title CYBERSHIELD - End-to-End Pipeline & SOC Command Center
color 0A

echo ====================================================================
echo   CYBERSHIELD // 5-Year Incident Analytics & ML Pipeline
echo ====================================================================
echo.

:: Ensure Python 3.11 is included in PATH
set "PATH=C:\Users\Kiran\AppData\Local\Programs\Python\Python311;C:\Users\Kiran\AppData\Local\Programs\Python\Python311\Scripts;%PATH%"
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

:: Navigate to project directory
cd /d "%~dp0"

echo [Step 1/4] Generating 5-Year Cyber Security Incident Telemetry (7,000 records)...
python src\generate_5_years.py
if %errorlevel% neq 0 goto error_handler

echo.
echo [Step 2/4] Training AI Incident Severity Classifier (Random Forest ML)...
python src\ml_model.py
if %errorlevel% neq 0 goto error_handler

echo.
echo [Step 3/4] Exporting Multi-Tab Styled Excel Workbook with Charts...
python src\export_excel.py
if %errorlevel% neq 0 goto error_handler

echo.
echo ====================================================================
echo  SUCCESS: All data synthesis, ML models, and reports prepared!
echo ====================================================================
echo.
echo Opening CYBERSHIELD Dashboard in your browser (http://localhost:8501)...
start "" "http://localhost:8501"
echo.

python -m streamlit run app.py
goto end

:error_handler
echo.
echo ====================================================================
echo [ERROR] An error occurred during pipeline execution.
echo ====================================================================
pause
exit /b 1

:end
