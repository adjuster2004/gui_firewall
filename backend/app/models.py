"""Модели данных приложения."""
from __future__ import annotations

import uuid
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

Chain = Literal["INPUT", "FORWARD", "OUTPUT"]
Target = Literal["ACCEPT", "DROP", "REJECT"]
Proto = Literal["tcp", "udp", "icmp", "any"]


def new_id() -> str:
    return "r" + uuid.uuid4().hex[:10]


class Rule(BaseModel):
    """Одно правило фаервола в модели «желаемого состояния»."""

    id: str = Field(default_factory=new_id)
    name: str = ""
    src: str = "any"          # источник: CIDR/IP/интерфейс или "any"
    dst: str = "any"          # назначение
    proto: Proto = "any"
    port: str = ""            # порт(ы) для tcp/udp: "22" или "80,443"
    target: Target = "ACCEPT"
    enabled: bool = True
    note: str = ""            # комментарий
    # дополнительные распространённые условия (сохраняются при регенерации)
    iface_in: str = ""        # -i <iface>
    iface_out: str = ""       # -o <iface>
    state: str = ""           # значение состояния, напр. "NEW" или "RELATED,ESTABLISHED"
    state_mod: str = ""       # каким модулем: "state" | "conntrack"
    reject_with: str = ""     # -j REJECT --reject-with <...>
    raw: Optional[str] = None  # исходная строка, если правило не разобрано (read-only)


class ChainRules(BaseModel):
    INPUT: List[Rule] = Field(default_factory=list)
    FORWARD: List[Rule] = Field(default_factory=list)
    OUTPUT: List[Rule] = Field(default_factory=list)

    def get(self, chain: str) -> List[Rule]:
        return getattr(self, chain)

    def set(self, chain: str, rules: List[Rule]) -> None:
        setattr(self, chain, rules)


NatKind = Literal["masquerade", "snat", "dnat"]


class NatRule(BaseModel):
    """Правило NAT (таблица nat).

    masquerade / snat — исходящий NAT (цепочка POSTROUTING): выпускают локальную
    сеть в интернет. dnat — проброс порта (цепочка PREROUTING): перенаправляет
    входящее соединение на внутренний хост.
    """

    id: str = Field(default_factory=new_id)
    name: str = ""
    enabled: bool = True
    note: str = ""
    kind: NatKind = "masquerade"
    proto: Proto = "any"          # для dnat: tcp/udp
    src: str = "any"              # -s (masquerade/snat: какой источник выпускаем)
    dst: str = "any"              # -d (dnat: на какой адрес пришло)
    dport: str = ""               # --dport (dnat)
    iface_in: str = ""            # -i (dnat, PREROUTING)
    iface_out: str = ""           # -o (masquerade/snat, POSTROUTING)
    to_source: str = ""           # snat: --to-source IP[:порт]
    to_dest: str = ""             # dnat: --to-destination IP[:порт]
    raw: Optional[str] = None

    @property
    def chain(self) -> str:
        return "PREROUTING" if self.kind == "dnat" else "POSTROUTING"


class FirewallState(BaseModel):
    """Полное желаемое состояние: таблица filter и таблица nat."""

    filter: ChainRules = Field(default_factory=ChainRules)
    nat: List[NatRule] = Field(default_factory=list)


# ---------- подключение и настройки ----------

class Connection(BaseModel):
    host: str = "192.0.2.10"
    port: int = 22
    username: str = "netadmin"
    auth: Literal["key", "password"] = "key"
    key_path: str = "~/.ssh/id_ed25519"
    password: str = ""          # SSH-пароль (если auth == password)
    use_sudo: bool = True
    sudo_password: str = ""      # пустой -> предполагаем NOPASSWD


def new_server_id() -> str:
    return "s" + uuid.uuid4().hex[:8]


class Server(BaseModel):
    """Профиль сервера: имя + параметры SSH-подключения."""

    id: str = Field(default_factory=new_server_id)
    name: str = "Новый сервер"
    connection: Connection = Field(default_factory=Connection)


class ApplyOptions(BaseModel):
    mode: Literal["dry", "live"] = "dry"
    persist: bool = True         # сохранять правила (netfilter-persistent / nft)
    backup: bool = True          # резервная копия перед применением


class Settings(BaseModel):
    servers: List[Server] = Field(default_factory=list)
    active_server: str = ""
    apply: ApplyOptions = Field(default_factory=ApplyOptions)
    gui_port: int = 8555
    bind_addr: str = "0.0.0.0"
    auto_detect: bool = True
    backend_override: Optional[str] = None  # ручной выбор бэкенда
    demo: bool = False           # демо-режим без реального SSH

    def active(self) -> Optional[Server]:
        for s in self.servers:
            if s.id == self.active_server:
                return s
        return self.servers[0] if self.servers else None

    def by_id(self, sid: str) -> Optional[Server]:
        for s in self.servers:
            if s.id == sid:
                return s
        return None


# ---------- ответы API ----------

class DetectedBackend(BaseModel):
    id: str                      # iptables | iptables-nft | nftables
    name: str
    detail: str
    available: bool
    active: bool


class ConnectionStatus(BaseModel):
    connected: bool
    host: str = ""
    hostname: str = ""           # uname -n сервера
    backend: Optional[str] = None
    backends: List[DetectedBackend] = Field(default_factory=list)
    sudo_ok: bool = False
    message: str = ""
    demo: bool = False
    supports_nat: bool = False


class PreviewResult(BaseModel):
    chain: str
    lines: List[str]


class ApplyResult(BaseModel):
    ok: bool
    message: str
    output: str = ""
    backup_id: Optional[str] = None
