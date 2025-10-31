@echo off
echo 🔹 Setting up your Python environment...

REM Create env if it doesn’t exist
if not exist env (
    echo 🆕 Creating virtual environment...
    python -m venv env
)

REM Activate the environment
call env\Scripts\activate

REM Install dependencies
echo 📦 Installing packages from requirements.txt...
pip install -r requirements.txt

echo ✅ Environment setup complete!
pause
