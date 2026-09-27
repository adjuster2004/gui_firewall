"""Определение доступного бэкенда фаервола на сервере."""
from __future__ import annotations

from typing import List, Optional, Tuple

from ..models import DetectedBackend
from ..ssh_client import SSHClient
from .base import FirewallBackend
from .iptables import IptablesBackend
from .nftables import NftBackend


def _iptables_variant(ssh: SSHClient) -> Optional[Tuple[str, str]]:
    """Вернуть (id, детальную версию) для iptables, если он есть."""
    path = ssh.which("iptables")
    if not path:
        return None
    ver = ssh.run("iptables --version").stdout.strip()
    # 'iptables v1.8.7 (nf_tables)' -> бэкенд nftables под капотом
    if "nf_tables" in ver:
        return ("iptables-nft", ver)
    return ("iptables", ver or "iptables")


def detect_backends(ssh: SSHClient) -> Tuple[List[DetectedBackend], Optional[str]]:
    """Опросить сервер и вернуть список бэкендов и id активного."""
    found: List[DetectedBackend] = []
    active: Optional[str] = None

    ipt = _iptables_variant(ssh)
    nft_path = ssh.which("nft")
    nft_ver = ssh.run("nft --version").stdout.strip() if nft_path else ""

    if ipt:
        bid, detail = ipt
        found.append(DetectedBackend(
            id=bid,
            name="iptables (legacy)" if bid == "iptables" else "iptables-nft",
            detail=detail,
            available=True,
            active=True,
        ))
        active = bid

    found.append(DetectedBackend(
        id="nftables",
        name="nftables",
        detail=nft_ver or "nft не установлен",
        available=bool(nft_path),
        active=active is None and bool(nft_path),
    ))
    if active is None and nft_path:
        active = "nftables"

    # если есть только iptables — добьём строку про nft уже добавленной выше;
    # если только nft — iptables в списке нет, добавим как недоступный
    if not ipt:
        found.insert(0, DetectedBackend(
            id="iptables", name="iptables (legacy)", detail="не установлен",
            available=False, active=False,
        ))
    return found, active


def make_backend(ssh: SSHClient, backend_id: str) -> FirewallBackend:
    if backend_id == "nftables":
        return NftBackend(ssh)
    if backend_id == "iptables-nft":
        return IptablesBackend(ssh, variant="iptables-nft")
    return IptablesBackend(ssh, variant="iptables")
