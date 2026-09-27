@echo off
REM Рубеж — запуск на Windows. Создаёт venv, ставит зависимости и стартует сервер.
setlocal
cd /d "%~dp0"

if not exist ".venv" (
    echo Создаю виртуальное окружение...
    python -m venv .venv
)
call ".venv\Scripts\activate.bat"

echo Проверяю зависимости...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

cd backend
echo.
echo Открой в браузере http://localhost:8555
echo (для демо без сервера:  start.bat --demo )
echo.
python run.py %*
endlocal
