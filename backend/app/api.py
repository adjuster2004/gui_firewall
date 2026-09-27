"""HTTP API приложения."""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .manager import manager
from .models import ApplyResult, NatRule, PreviewResult, Rule, Settings

router = APIRouter(prefix="/api")


# ---------- статус / настройки ----------

@router.get("/status")
def status():
    return manager.get_status()


@router.get("/settings", response_model=Settings)
def get_settings():
    # Не отдаём секреты в браузер: пароли по всем серверам заменяем на пустые.
    s = manager.get_settings().model_copy(deep=True)
    for srv in s.servers:
        srv.connection.password = ""
        srv.connection.sudo_password = ""
    return s


@router.put("/settings", response_model=Settings)
def put_settings(s: Settings):
    return manager.update_settings(s)


@router.post("/connect")
def connect():
    manager.connect()
    return manager.get_status()


@router.post("/test")
def test_connection():
    """Проверить подключение активного сервера с сохранёнными параметрами."""
    manager.connect()
    return manager.get_status()


@router.post("/disconnect")
def disconnect():
    manager.disconnect()
    return {"ok": True}


@router.get("/interfaces")
def interfaces():
    return {"interfaces": manager.list_interfaces()}


# ---------- серверы ----------

@router.get("/servers")
def list_servers():
    return {"servers": manager.list_servers(), "active": manager.active}


class AddServerBody(BaseModel):
    name: str = ""


@router.post("/servers")
def add_server(body: AddServerBody):
    srv = manager.add_server(body.name)
    return {"id": srv.id, "name": srv.name}


@router.post("/servers/{server_id}/activate")
def activate_server(server_id: str):
    try:
        manager.activate(server_id)
        return manager.get_status()
    except KeyError:
        raise HTTPException(404, "Сервер не найден")


@router.delete("/servers/{server_id}")
def delete_server(server_id: str):
    try:
        manager.delete_server(server_id)
        return {"ok": True}
    except ValueError as e:
        raise HTTPException(400, str(e))


# ---------- правила ----------

@router.get("/rules")
def get_rules():
    st = manager.get_status()
    return {
        "rules": manager.list_rules().model_dump(),
        "nat": [r.model_dump() for r in manager.list_nat()],
        "dirty": manager.dirty(),
        "connected": st.get("connected"),
        "backend": st.get("backend"),
        "demo": st.get("demo"),
        "supports_nat": st.get("supports_nat"),
    }


@router.post("/rules/{chain}", response_model=Rule)
def add_rule(chain: str, rule: Rule):
    try:
        return manager.add_rule(chain, rule)
    except (ValueError, KeyError) as e:
        raise HTTPException(400, str(e))


@router.patch("/rules/{chain}/{rule_id}", response_model=Rule)
def update_rule(chain: str, rule_id: str, patch: dict):
    try:
        return manager.update_rule(chain, rule_id, patch)
    except KeyError:
        raise HTTPException(404, "Правило не найдено")
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/rules/{chain}/{rule_id}")
def delete_rule(chain: str, rule_id: str):
    manager.delete_rule(chain, rule_id)
    return {"ok": True}


class ReorderBody(BaseModel):
    order: List[str]


@router.post("/rules/{chain}/reorder")
def reorder(chain: str, body: ReorderBody):
    try:
        manager.reorder(chain, body.order)
        return {"ok": True}
    except ValueError as e:
        raise HTTPException(400, str(e))


# ---------- NAT ----------

@router.post("/nat", response_model=NatRule)
def add_nat(rule: NatRule):
    return manager.add_nat(rule)


@router.patch("/nat/{rule_id}", response_model=NatRule)
def update_nat(rule_id: str, patch: dict):
    try:
        return manager.update_nat(rule_id, patch)
    except KeyError:
        raise HTTPException(404, "Правило не найдено")


@router.delete("/nat/{rule_id}")
def delete_nat(rule_id: str):
    manager.delete_nat(rule_id)
    return {"ok": True}


@router.post("/nat/reorder")
def reorder_nat(body: ReorderBody):
    try:
        manager.reorder_nat(body.order)
        return {"ok": True}
    except ValueError as e:
        raise HTTPException(400, str(e))


# ---------- предпросмотр / применение ----------

@router.get("/preview/{chain}", response_model=PreviewResult)
def preview(chain: str):
    try:
        context = {"table": "nat"} if chain == "nat" else {"table": "filter", "chain": chain}
        return manager.preview(context)
    except (RuntimeError, ValueError) as e:
        raise HTTPException(400, str(e))


@router.post("/apply", response_model=ApplyResult)
def apply():
    try:
        return manager.apply()
    except RuntimeError as e:
        raise HTTPException(400, str(e))


@router.post("/revert")
def revert():
    manager.revert()
    return {"ok": True}
