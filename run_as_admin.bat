@echo off
cd /d "%~dp0"
set PATH=%~dp0venv\Scripts;%PATH%
call venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python src\main.py
pause
