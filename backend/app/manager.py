"""Сессия приложения: несколько серверов, состояние правил, применение.

Для каждого сервера ведётся отдельная сессия: своё подключение SSH, свой бэкенд
и своё «желаемое состояние» (filter + nat). Несохранённые правки не теряются при
переключении между серверами в пределах запущенного приложения.
"""
from __future__ import annotations

import threading
from typing import Dict, List

from . import store
from .firewall import detect_backends, make_backend
from .firewall.base import CHAINS
from .firewall.demo import DemoBackend
from .models import (
    ApplyResult,
    ChainRules,
    ConnectionStatus,
    DetectedBackend,
    FirewallState,
    NatRule,
    PreviewResult,
    Rule,
    Server,
    Settings,
)
from .ssh_client import SSHClient, SSHError


_DEMO_IFACES = [
    {"name": "lo", "ipv4": ["127.0.0.1/8"], "label": "lo · 127.0.0.1/8"},
    {"name": "eth0", "ipv4": ["10.146.2.1/27"], "label": "eth0 · 10.146.2.1/27"},
    {"name": "eth1", "ipv4": ["10.144.3.1/29"], "label": "eth1 · 10.144.3.1/29 (аплинк)"},
    {"name": "eth2", "ipv4": ["10.144.1.17/29"], "label": "eth2 · 10.144.1.17/29"},
    {"name": "eth3", "ipv4": ["10.144.1.1/29"], "label": "eth3 · 10.144.1.1/29"},
    {"name": "eth11", "ipv4": ["10.144.1.65/24"], "label": "eth11 · 10.144.1.65/24"},
    {"name": "eth12", "ipv4": ["10.144.2.1/24"], "label": "eth12 · 10.144.2.1/24"},
]


class _Session:
    def __init__(self, state: FirewallState):
        self.state = state
        self.applied = state.model_dump_json()
        self.backend = None
        self.ssh = None
        self.status = ConnectionStatus(connected=False)


class Manager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.settings: Settings = store.load_settings()
        self.sessions: Dict[str, _Session] = {}
        self.active: str = self.settings.active_server
        self._session(self.active)

    # ---------- сессии ----------

    def _session(self, sid: str) -> _Session:
        if sid not in self.sessions:
            self.sessions[sid] = _Session(store.load_state(sid) or FirewallState())
        return self.sessions[sid]

    def _cur(self) -> _Session:
        return self._session(self.active)

    # ---------- настройки ----------

    def get_settings(self) -> Settings:
        with self._lock:
            return self.settings

    def update_settings(self, s: Settings) -> Settings:
        with self._lock:
            # Пустой пароль означает «не менять» — берём прежний секрет того же сервера.
            for srv in s.servers:
                old = self.settings.by_id(srv.id)
                if old:
                    if not srv.connection.password:
                        srv.connection.password = old.connection.password
                    if not srv.connection.sudo_password:
                        srv.connection.sudo_password = old.connection.sudo_password
            if not s.by_id(s.active_server):
                s.active_server = s.servers[0].id if s.servers else ""
            self.settings = s
            self.active = s.active_server
            store.save_settings(s)
            return s

    # ---------- серверы ----------

    def list_servers(self) -> List[dict]:
        with self._lock:
            out = []
            for srv in self.settings.servers:
                sess = self.sessions.get(srv.id)
                out.append({
                    "id": srv.id,
                    "name": srv.name,
                    "host": srv.connection.host,
                    "connected": bool(sess and sess.status.connected),
                    "active": srv.id == self.active,
                })
            return out

    def add_server(self, name: str = "") -> Server:
        with self._lock:
            n = (name or "").strip() or f"Сервер {len(self.settings.servers) + 1}"
            srv = Server(name=n)
            self.settings.servers.append(srv)
            store.save_settings(self.settings)
            return srv

    def delete_server(self, sid: str) -> None:
        with self._lock:
            if len(self.settings.servers) <= 1:
                raise ValueError("Нельзя удалить единственный сервер.")
            self.settings.servers = [x for x in self.settings.servers if x.id != sid]
            sess = self.sessions.pop(sid, None)
            if sess and sess.ssh:
                try:
                    sess.ssh.close()
                except Exception:
                    pass
            store.delete_state(sid)
            if self.active == sid:
                self.active = self.settings.servers[0].id
                self.settings.active_server = self.active
            store.save_settings(self.settings)

    def activate(self, sid: str) -> ConnectionStatus:
        with self._lock:
            if not self.settings.by_id(sid):
                raise KeyError("Сервер не найден")
            self.active = sid
            self.settings.active_server = sid
            store.save_settings(self.settings)
            sess = self._session(sid)
            if sess.status.connected:
                return sess.status
            return self.connect()

    # ---------- подключение ----------

    def connect(self) -> ConnectionStatus:
        with self._lock:
            sess = self._cur()
            srv = self.settings.active()
            if srv is None:
                sess.status = ConnectionStatus(connected=False, message="Нет активного сервера.")
                return sess.status

            if self.settings.demo:
                sess.backend = DemoBackend()
                self._load_state(sess, sess.backend.fetch())
                sess.status = ConnectionStatus(
                    connected=True, host="demo", hostname=srv.name,
                    backend="iptables", sudo_ok=True, demo=True, supports_nat=True,
                    message="Демо-режим: данные в памяти, реального SSH нет.",
                    backends=[DetectedBackend(id="iptables", name="iptables (демо)",
                                              detail="встроенные демо-данные", available=True, active=True)],
                )
                return sess.status

            try:
                if sess.ssh:
                    try:
                        sess.ssh.close()
                    except Exception:
                        pass
                ssh = SSHClient(srv.connection)
                ssh.connect()
                hostname = ssh.run("uname -n").stdout.strip()
                sudo_ok = ssh.check_sudo()
                backends, active = detect_backends(ssh)
                s = self.settings
                chosen = s.backend_override if (not s.auto_detect and s.backend_override) else active
                if not chosen:
                    ssh.close()
                    sess.status = ConnectionStatus(connected=False, host=srv.connection.host,
                                                   message="На сервере не найден ни iptables, ни nft.")
                    return sess.status
                sess.backend = make_backend(ssh, chosen)
                self._load_state(sess, sess.backend.fetch())
                sess.ssh = ssh
                sess.status = ConnectionStatus(
                    connected=True, host=srv.connection.host, hostname=hostname,
                    backend=chosen, backends=backends, sudo_ok=sudo_ok,
                    supports_nat=getattr(sess.backend, "supports_nat", False),
                    message="Подключено." if sudo_ok else "Подключено, но sudo недоступен.",
                )
            except SSHError as e:
                sess.status = ConnectionStatus(connected=False, host=srv.connection.host, message=str(e))
            return sess.status

    def _load_state(self, sess: _Session, state: FirewallState) -> None:
        sess.state = state
        sess.applied = state.model_dump_json()
        store.save_state(self.active, state)

    def list_interfaces(self) -> List[dict]:
        """Сетевые интерфейсы активного сервера с их IPv4-адресами."""
        with self._lock:
            if self.settings.demo:
                return _DEMO_IFACES
            sess = self._cur()
            if not sess.ssh:
                return []
            try:
                res = sess.ssh.run("ip -o -4 addr show")
            except Exception:
                return []
            order: List[str] = []
            ips: Dict[str, list] = {}
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4 or "inet" not in parts:
                    continue
                name = parts[1]
                cidr = parts[parts.index("inet") + 1]
                if name not in ips:
                    ips[name] = []
                    order.append(name)
                ips[name].append(cidr)
            return [{"name": n, "ipv4": ips[n],
                     "label": n + " · " + ", ".join(ips[n])} for n in order]

    def get_status(self) -> dict:
        with self._lock:
            srv = self.settings.active()
            st = self._cur().status.model_dump()
            st["active_server"] = self.active
            st["active_name"] = srv.name if srv else ""
            st["dirty"] = self.dirty()
            return st

    def disconnect(self) -> None:
        with self._lock:
            sess = self._cur()
            try:
                if sess.ssh:
                    sess.ssh.close()
            except Exception:
                pass
            sess.ssh = None
            sess.backend = None
            sess.status = ConnectionStatus(connected=False)

    # ---------- общее ----------

    def _require_backend(self):
        b = self._cur().backend
        if b is None:
            raise RuntimeError("Нет подключения. Сначала подключитесь на вкладке «Настройки».")
        return b

    def dirty(self) -> bool:
        sess = self._cur()
        return sess.state.model_dump_json() != sess.applied

    def _save(self) -> None:
        store.save_state(self.active, self._cur().state)

    def _check_chain(self, chain: str) -> None:
        if chain not in CHAINS:
            raise ValueError(f"Неизвестная цепочка: {chain}")

    # ---------- правила filter ----------

    def list_rules(self) -> ChainRules:
        with self._lock:
            return self._cur().state.filter

    def add_rule(self, chain: str, rule: Rule) -> Rule:
        with self._lock:
            self._check_chain(chain)
            self._cur().state.filter.get(chain).append(rule)
            self._save()
            return rule

    def update_rule(self, chain: str, rule_id: str, patch: dict) -> Rule:
        with self._lock:
            self._check_chain(chain)
            lst = self._cur().state.filter.get(chain)
            for idx, r in enumerate(lst):
                if r.id == rule_id:
                    data = r.model_dump()
                    data.update({k: v for k, v in patch.items() if k in data and k != "id"})
                    lst[idx] = Rule.model_validate(data)
                    self._save()
                    return lst[idx]
            raise KeyError("Правило не найдено")

    def delete_rule(self, chain: str, rule_id: str) -> None:
        with self._lock:
            self._check_chain(chain)
            f = self._cur().state.filter
            f.set(chain, [r for r in f.get(chain) if r.id != rule_id])
            self._save()

    def reorder(self, chain: str, order: List[str]) -> None:
        with self._lock:
            self._check_chain(chain)
            f = self._cur().state.filter
            by_id = {r.id: r for r in f.get(chain)}
            if set(order) != set(by_id):
                raise ValueError("Список идентификаторов не совпадает с цепочкой")
            f.set(chain, [by_id[i] for i in order])
            self._save()

    # ---------- правила NAT ----------

    def list_nat(self) -> List[NatRule]:
        with self._lock:
            return self._cur().state.nat

    def add_nat(self, rule: NatRule) -> NatRule:
        with self._lock:
            self._cur().state.nat.append(rule)
            self._save()
            return rule

    def update_nat(self, rule_id: str, patch: dict) -> NatRule:
        with self._lock:
            nat = self._cur().state.nat
            for idx, r in enumerate(nat):
                if r.id == rule_id:
                    data = r.model_dump()
                    data.update({k: v for k, v in patch.items() if k in data and k != "id"})
                    nat[idx] = NatRule.model_validate(data)
                    self._save()
                    return nat[idx]
            raise KeyError("Правило не найдено")

    def delete_nat(self, rule_id: str) -> None:
        with self._lock:
            cur = self._cur()
            cur.state.nat = [r for r in cur.state.nat if r.id != rule_id]
            self._save()

    def reorder_nat(self, order: List[str]) -> None:
        with self._lock:
            cur = self._cur()
            by_id = {r.id: r for r in cur.state.nat}
            if set(order) != set(by_id):
                raise ValueError("Список идентификаторов не совпадает")
            cur.state.nat = [by_id[i] for i in order]
            self._save()

    # ---------- предпросмотр и применение ----------

    def preview(self, context: dict) -> PreviewResult:
        with self._lock:
            backend = self._require_backend()
            label = "nat" if context.get("table") == "nat" else context.get("chain", "INPUT")
            return PreviewResult(chain=label, lines=backend.build_document(context, self._cur().state))

    def apply(self) -> ApplyResult:
        with self._lock:
            sess = self._cur()
            backend = self._require_backend()
            res = backend.apply(sess.state, self.settings.apply)
            if res.ok and self.settings.apply.mode == "live":
                sess.applied = sess.state.model_dump_json()
                self._save()
            return res

    def revert(self) -> None:
        with self._lock:
            sess = self._cur()
            sess.state = FirewallState.model_validate_json(sess.applied)
            self._save()


manager = Manager()
