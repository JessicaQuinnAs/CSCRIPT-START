REM ===== Windows setup script for Secret Monitor =====

REM 1. Create and activate a Python virtual environment
python -m venv venv
call venv\Scripts\activate

REM 2. Upgrade pip to the latest version
pip install --upgrade pip

REM 3. Install required Python packages
pip install fastapi uvicorn python-dotenv websockets watchdog pillow pytesseract dnspython base58 requests

REM 4. Install Tesseract OCR engine
REM    - Download the Windows installer (e.g., from https://github.com/UB-Mannheim/tesseract/wiki)
REM    - Run the MSI and follow prompts
REM    - Ensure the installation path is added to your PATH

REM 5. Place .env next to secret_monitor.py

REM Launch:
REM    python secret_monitor.py
