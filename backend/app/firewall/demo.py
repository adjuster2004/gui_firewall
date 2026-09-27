"""Демо-бэкенд без SSH: состояние живёт в памяти процесса.

Позволяет запустить и посмотреть всё приложение целиком, не имея под рукой
Linux-сервера. Применение просто фиксирует состояние и возвращает те же команды,
что сгенерировал бы настоящий бэкенд iptables.
"""
from __future__ import annotations

from typing import List

from ..models import ApplyOptions, ApplyResult, ChainRules, FirewallState, NatRule, Rule
from .base import CHAINS, FirewallBackend
from .iptables import IptablesBackend


def _seed() -> FirewallState:
    cr = ChainRules()
    cr.INPUT = [
        Rule(name="Loopback", raw="-A INPUT -i lo -j ACCEPT", note="внутренний интерфейс"),
        Rule(name="Установленные соединения", proto="any", target="ACCEPT",
             state="RELATED,ESTABLISHED", state_mod="conntrack"),
        Rule(name="SSH из офиса", src="203.0.113.0/24", proto="tcp", port="22", target="ACCEPT", note="управление"),
        Rule(name="HTTP / HTTPS", proto="tcp", port="80,443", target="ACCEPT", note="веб-сервер"),
        Rule(name="Пинг (ICMP)", proto="icmp", target="ACCEPT", note="echo-request"),
        Rule(name="Старый VPN-шлюз", src="198.51.100.7", proto="udp", port="1194", target="ACCEPT",
             note="выведен из эксплуатации", enabled=False),
        Rule(name="Блокировка Telnet", proto="tcp", port="23", target="DROP"),
    ]
    cr.FORWARD = [
        Rule(name="10.145.1.2 в интернет", src="10.145.1.2", target="ACCEPT", note="разрешённая машина"),
        Rule(name="Ответы к 10.145.1.2", dst="10.145.1.2", target="ACCEPT"),
        Rule(name="Отклонить остальную пересылку", target="REJECT"),
    ]
    cr.OUTPUT = [
        Rule(name="Разрешить весь исходящий", target="ACCEPT"),
    ]
    nat = [
        NatRule(name="Маскарадинг 10.145.1.2", kind="masquerade", src="10.145.1.2",
                iface_out="eth0", note="выпуск в интернет"),
        NatRule(name="Проброс tcp/8080 → 10.145.1.5:80", kind="dnat", proto="tcp",
                dport="8080", iface_in="eth0", to_dest="10.145.1.5:80", note="веб внутрь"),
    ]
    return FirewallState(filter=cr, nat=nat)


class DemoBackend(FirewallBackend):
    id = "iptables"
    name = "iptables (демо)"
    supports_nat = True

    def __init__(self) -> None:
        self._state = _seed()
        # вспомогательный экземпляр только для генерации строк
        self._h = IptablesBackend.__new__(IptablesBackend)
        self._h.variant = "iptables"
        self._h._policies = {"INPUT": "DROP", "FORWARD": "DROP", "OUTPUT": "ACCEPT"}
        self._h._preserved = []
        self._h._custom_chain_decls = []
        self._h._nat_policies = {"PREROUTING": "ACCEPT", "INPUT": "ACCEPT", "OUTPUT": "ACCEPT", "POSTROUTING": "ACCEPT"}
        self._h._nat_preserved = []
        self._h._nat_chain_decls = []

    def fetch(self) -> FirewallState:
        return self._state.model_copy(deep=True)

    def build_document(self, context: dict, state: FirewallState) -> List[str]:
        return self._h.build_document(context, state)

    def apply(self, state: FirewallState, opts: ApplyOptions) -> ApplyResult:
        self._state = state.model_copy(deep=True)
        n = sum(len([r for r in state.filter.get(c) if r.enabled]) for c in CHAINS)
        nat_n = len([r for r in state.nat if r.enabled])
        if opts.mode == "dry":
            return ApplyResult(ok=True, message="Демо-режим: сухой прогон, ничего не менялось.",
                               output=f"filter: {n}, nat: {nat_n}")
        return ApplyResult(ok=True, message="Демо-режим: изменения зафиксированы в памяти.",
                           output=f"Активных правил — filter: {n}, nat: {nat_n}")
