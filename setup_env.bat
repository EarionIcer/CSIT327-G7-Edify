@echo off
chcp 65001 >nul
title 🔹 Python Environment Setup

echo 🔹 Setting up your Python environment...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not added to PATH.
    echo 👉 Please install Python 3.8 or higher and make sure it's added to PATH.
    echo.
    pause
    exit /b
)

REM Create virtual environment if it doesn’t exist
if not exist "env" (
    echo 🆕 Creating virtual environment...
    python -m venv env
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment.
        echo.
        pause
        exit /b
    )
)

REM Activate the environment
echo 🔄 Activating virtual environment...
call "env\Scripts\activate.bat"
if errorlevel 1 (
    echo ❌ Failed to activate virtual environment.
    echo.
    pause
    exit /b
)

REM Upgrade pip to latest version
echo ⬆️  Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies if requirements.txt exists
if exist "requirements.txt" (
    echo 📦 Installing dependencies from requirements.txt...
    pip install -r requirements.txt
) else (
    echo ⚠️  No requirements.txt file found — skipping package installation.
)

echo.
echo ✅ Environment setup complete!
echo 🐍 Virtual environment is now active.
echo.
pause
