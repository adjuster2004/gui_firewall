"""Запуск сервера «Рубеж».

Порт и адрес берутся из сохранённых настроек (~/.rubezh/settings.json),
по умолчанию 0.0.0.0:8555. Флаги:

    python run.py                # обычный запуск
    python run.py --demo         # демо-режим (без SSH), удобно для первого знакомства
    python run.py --port 9000    # переопределить порт
"""
from __future__ import annotations

import argparse
import os
import sys

import uvicorn

from app import store


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def main() -> int:
    p = argparse.ArgumentParser(description="Рубеж — GUI управления фаерволом")
    p.add_argument("--demo", action="store_true", help="демо-режим без реального SSH")
    p.add_argument("--port", type=int, default=None, help="порт GUI (по умолчанию из настроек: 8555)")
    p.add_argument("--host", default=None, help="адрес привязки (по умолчанию 0.0.0.0)")
    args = p.parse_args()

    s = store.load_settings()
    if args.demo or _env_flag("RUBEZH_DEMO"):
        s.demo = True
    if os.environ.get("RUBEZH_PORT"):
        args.port = args.port or int(os.environ["RUBEZH_PORT"])
    port = args.port or s.gui_port or 8555
    host = args.host or s.bind_addr or "0.0.0.0"
    s.gui_port, s.bind_addr = port, host
    store.save_settings(s)

    print(f"Рубеж запускается на http://{host}:{port}"
          + ("  [демо-режим]" if s.demo else ""))
    uvicorn.run("app.main:app", host=host, port=port, reload=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
