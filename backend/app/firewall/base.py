"""Базовый интерфейс бэкенда фаервола."""
from __future__ import annotations

import abc
from typing import List

from ..models import ApplyOptions, ApplyResult, FirewallState
from ..ssh_client import SSHClient

CHAINS = ["INPUT", "FORWARD", "OUTPUT"]


class FirewallBackend(abc.ABC):
    """Единый интерфейс поверх iptables / nftables / демо."""

    id: str = "base"
    name: str = "base"
    supports_nat: bool = False

    @abc.abstractmethod
    def fetch(self) -> FirewallState:
        """Считать текущее состояние сервера (таблицы filter и nat)."""

    @abc.abstractmethod
    def build_document(self, context: dict, state: FirewallState) -> List[str]:
        """Строки для предпросмотра. context={'table':'filter','chain':..} | {'table':'nat'}"""

    @abc.abstractmethod
    def apply(self, state: FirewallState, opts: ApplyOptions) -> ApplyResult:
        """Применить состояние на сервере (атомарно, с бэкапом)."""


class SSHBackend(FirewallBackend):
    """Общая часть для бэкендов, работающих по SSH."""

    def __init__(self, ssh: SSHClient):
        self.ssh = ssh
