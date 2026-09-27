"""Бэкенд nftables (nft). Управляет таблицей `inet filter`.

Работает с цепочками, привязанными к хукам input/forward/output. Простые правила
раскладываются на столбцы приложения; всё остальное сохраняется «сырым» и
переносится без изменений. Применение атомарно: один файл `nft -f` со сбросом
управляемых цепочек и повторным добавлением правил в рамках одной транзакции.

Примечание: считается, что базовые цепочки лежат в таблице `inet filter`
(конфигурация nftables по умолчанию в Debian/Ubuntu). Иначе бэкенд сообщит, что
таблица не найдена.
"""
from __future__ import annotations

import re
import shlex
import time
from typing import Dict, List

from ..models import ApplyOptions, ApplyResult, ChainRules, FirewallState, Rule
from ..ssh_client import SSHClient
from .base import CHAINS, SSHBackend

_HOOK_TO_CHAIN = {"input": "INPUT", "forward": "FORWARD", "output": "OUTPUT"}


class NftBackend(SSHBackend):
    id = "nftables"
    name = "nftables"
    supports_nat = False

    def __init__(self, ssh: SSHClient):
        super().__init__(ssh)
        self.table = ("inet", "filter")
        self._chain_names: Dict[str, str] = {}   # INPUT -> реальное имя цепочки
        self._policies: Dict[str, str] = {}
        self._table_ok = False

    # ---------- чтение ----------

    def fetch(self) -> FirewallState:
        return FirewallState(filter=self._fetch_filter(), nat=[])

    def _fetch_filter(self) -> ChainRules:
        res = self.ssh.run("nft -a list table inet filter", sudo=True)
        cr = ChainRules()
        if not res.ok:
            self._table_ok = False
            return cr
        self._table_ok = True
        cur_chain = None
        cur_std = None
        rules: Dict[str, List[Rule]] = {c: [] for c in CHAINS}
        for raw in res.stdout.splitlines():
            line = raw.strip()
            m = re.match(r"chain\s+(\S+)\s*\{", line)
            if m:
                cur_chain = m.group(1)
                cur_std = None
                continue
            if line == "}":
                cur_chain = cur_std = None
                continue
            hook = re.search(r"hook\s+(\w+)", line)
            if hook and cur_chain:
                std = _HOOK_TO_CHAIN.get(hook.group(1))
                if std:
                    cur_std = std
                    self._chain_names[std] = cur_chain
                    pol = re.search(r"policy\s+(\w+)", line)
                    self._policies[std] = pol.group(1) if pol else "accept"
                continue
            if cur_std and line and not line.startswith("type "):
                rule = self._parse_rule(re.sub(r"\s*#\s*handle\s+\d+\s*$", "", line))
                if rule:
                    rules[cur_std].append(rule)
        for c in CHAINS:
            cr.set(c, rules[c])
        return cr

    def _parse_rule(self, text: str) -> Rule | None:
        text = text.strip()
        if not text:
            return None
        src = dst = "any"
        proto = "any"
        port = ""
        target = ""
        note = ""
        simple = True

        m = re.search(r"comment\s+\"([^\"]*)\"", text)
        if m:
            note = m.group(1)
            text = text[: m.start()].strip() + " " + text[m.end():].strip()

        m = re.search(r"ip6?\s+saddr\s+(\S+)", text)
        if m:
            src = m.group(1)
        m = re.search(r"ip6?\s+daddr\s+(\S+)", text)
        if m:
            dst = m.group(1)
        m = re.search(r"(tcp|udp)\s+dport\s+\{([^}]+)\}", text)
        if m:
            proto = m.group(1)
            port = ",".join(p.strip() for p in m.group(2).split(","))
        else:
            m = re.search(r"(tcp|udp)\s+dport\s+(\d+)", text)
            if m:
                proto = m.group(1)
                port = m.group(2)
        if re.search(r"ip\s+protocol\s+icmp|icmp\s+type", text):
            proto = "icmp"

        if re.search(r"\baccept\b", text):
            target = "ACCEPT"
        elif re.search(r"\bdrop\b", text):
            target = "DROP"
        elif re.search(r"\breject\b", text):
            target = "REJECT"
        else:
            simple = False

        # если остались непонятные конструкции (интерфейсы, ct state, meta, jump ...) — сырое
        if re.search(r"\b(iifname|oifname|ct|meta|jump|goto|counter\s+packets|log|dnat|snat|masquerade)\b", text):
            simple = False

        if not simple:
            return Rule(name=note or "custom", note=note or "нестандартное правило", raw=text.strip())
        return Rule(
            name=note or f"{target.lower()} {proto}{(':' + port) if port else ''}",
            src=src, dst=dst, proto=proto if proto in ("tcp", "udp", "icmp") else "any",
            port=port, target=target, note=note,
        )

    # ---------- генерация ----------

    def _rule_to_text(self, r: Rule) -> str:
        if r.raw:
            return r.raw
        parts: List[str] = []
        if r.src and r.src != "any":
            parts.append(f"ip saddr {r.src}")
        if r.dst and r.dst != "any":
            parts.append(f"ip daddr {r.dst}")
        if r.proto in ("tcp", "udp") and r.port:
            ports = [p.strip() for p in r.port.split(",") if p.strip()]
            if len(ports) > 1:
                parts.append(f"{r.proto} dport {{ {', '.join(ports)} }}")
            else:
                parts.append(f"{r.proto} dport {ports[0]}")
        elif r.proto == "icmp":
            parts.append("ip protocol icmp")
        parts.append({"ACCEPT": "accept", "DROP": "drop", "REJECT": "reject"}[r.target])
        if r.note:
            parts.append(f'comment "{r.note}"')
        return " ".join(parts)

    def build_document(self, context: dict, state: FirewallState) -> List[str]:
        if context.get("table") == "nat":
            return ["# NAT через nftables пока не поддерживается в «Рубеже».",
                    "# Используйте бэкенд iptables/iptables-nft для управления NAT."]
        chain = context.get("chain", "INPUT")
        name = self._chain_names.get(chain, chain.lower())
        out = ["# nft -f (атомарная транзакция)",
               f"flush chain inet filter {name}"]
        for r in state.filter.get(chain):
            if not r.enabled:
                out.append(f"# (выкл.) {r.name}")
                continue
            out.append(f"add rule inet filter {name} {self._rule_to_text(r)}")
        return out

    # ---------- применение ----------

    def apply(self, state: FirewallState, opts: ApplyOptions) -> ApplyResult:
        rules = state.filter
        if not self._table_ok and not self._chain_names:
            self._fetch_filter()
        backup_id = None
        if opts.backup:
            backup_id = f"rubezh-{int(time.time())}"
            b = self.ssh.run(f"nft list ruleset > /tmp/{backup_id}.nft", sudo=True)
            if not b.ok:
                return ApplyResult(ok=False, message="Не удалось снять резервную копию", output=b.stderr)

        doc_lines: List[str] = []
        for ch in CHAINS:
            name = self._chain_names.get(ch)
            if not name:
                continue
            doc_lines.append(f"flush chain inet filter {name}")
        for ch in CHAINS:
            name = self._chain_names.get(ch)
            if not name:
                continue
            for r in rules.get(ch):
                if r.enabled:
                    doc_lines.append(f"add rule inet filter {name} {self._rule_to_text(r)}")
        document = "\n".join(doc_lines) + "\n"

        cmd = f"nft -f - <<'RUBEZH_EOF'\n{document}RUBEZH_EOF"
        res = self.ssh.run_script(cmd, sudo=True)
        if not res.ok:
            if backup_id:
                self.ssh.run_script(f"nft flush ruleset && nft -f /tmp/{backup_id}.nft", sudo=True)
            return ApplyResult(ok=False,
                               message="Ошибка применения — правила откачены из резервной копии.",
                               output=res.stderr or res.stdout, backup_id=backup_id)

        persist_note = ""
        if opts.persist:
            persist_note = self._persist()
        return ApplyResult(ok=True,
                           message="Правила применены." + (f" {persist_note}" if persist_note else ""),
                           output=res.stdout, backup_id=backup_id)

    def _persist(self) -> str:
        if self.ssh.which("netfilter-persistent"):
            r = self.ssh.run("netfilter-persistent save", sudo=True)
            return "Сохранено через netfilter-persistent." if r.ok else "Сохранить не удалось."
        check = self.ssh.run("test -f /etc/nftables.conf")
        if check.ok:
            r = self.ssh.run("nft list ruleset > /etc/nftables.conf", sudo=True)
            return "Сохранено в /etc/nftables.conf." if r.ok else "Сохранить не удалось."
        return "Постоянное сохранение недоступно."
