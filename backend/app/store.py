"""Файловое хранилище настроек и правил.

Настройки (включая профили серверов и пароли) и «желаемое состояние» правил для
каждого сервера хранятся в JSON рядом с приложением, на машине администратора.
По сети пароли уходят только на целевой сервер по SSH.
"""
from __future__ import annotations

import json
import os
import re
import threading
from typing import Optional

from .models import Connection, FirewallState, Server, Settings

_DIR = os.environ.get("RUBEZH_DATA", os.path.join(os.path.expanduser("~"), ".rubezh"))
_SETTINGS = os.path.join(_DIR, "settings.json")

_lock = threading.Lock()


def _ensure_dir() -> None:
    os.makedirs(_DIR, exist_ok=True)


def _rules_path(server_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]", "", server_id) or "default"
    return os.path.join(_DIR, f"rules_{safe}.json")


def _migrate(data: dict) -> dict:
    """Старый формат (одиночный connection) → список серверов."""
    if "servers" not in data:
        conn = data.pop("connection", None) or {}
        srv = Server(name="Сервер 1", connection=Connection.model_validate(conn))
        data["servers"] = [srv.model_dump()]
        data["active_server"] = srv.id
    return data


def load_settings() -> Settings:
    with _lock:
        try:
            with open(_SETTINGS, "r", encoding="utf-8") as f:
                s = Settings.model_validate(_migrate(json.load(f)))
        except (FileNotFoundError, ValueError):
            s = Settings()
    # гарантируем хотя бы один сервер
    if not s.servers:
        srv = Server(name="Сервер 1")
        s.servers = [srv]
        s.active_server = srv.id
    if not s.active_server or not s.by_id(s.active_server):
        s.active_server = s.servers[0].id
    return s


def save_settings(s: Settings) -> None:
    _ensure_dir()
    with _lock:
        with open(_SETTINGS, "w", encoding="utf-8") as f:
            json.dump(s.model_dump(), f, ensure_ascii=False, indent=2)


def load_state(server_id: str) -> Optional[FirewallState]:
    with _lock:
        try:
            with open(_rules_path(server_id), "r", encoding="utf-8") as f:
                return FirewallState.model_validate(json.load(f))
        except (FileNotFoundError, ValueError):
            return None


def save_state(server_id: str, state: FirewallState) -> None:
    _ensure_dir()
    with _lock:
        with open(_rules_path(server_id), "w", encoding="utf-8") as f:
            json.dump(state.model_dump(), f, ensure_ascii=False, indent=2)


def delete_state(server_id: str) -> None:
    with _lock:
        try:
            os.remove(_rules_path(server_id))
        except FileNotFoundError:
            pass


def data_dir() -> str:
    return _DIR
