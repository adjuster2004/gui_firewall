#!/usr/bin/env bash
# Рубеж — запуск на Linux/macOS. Создаёт venv, ставит зависимости и стартует сервер.
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "Создаю виртуальное окружение..."
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "Проверяю зависимости..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

cd backend
echo
echo "Открой в браузере http://localhost:8555"
echo "(для демо без сервера:  ./start.sh --demo )"
echo
exec python run.py "$@"
