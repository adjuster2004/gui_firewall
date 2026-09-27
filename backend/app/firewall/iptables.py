"""Бэкенд iptables (подходит и для legacy, и для iptables-nft).

Стратегия:
* Чтение — `iptables-save -t filter`, разбор строк `-A` в модель. Строки, которые
  не раскладываются на наши столбцы (conntrack, jump в кастомные цепочки и т.п.),
  сохраняются как «сырые» и переносятся без изменений.
* Применение — сборка полного документа таблицы `filter` и атомарная загрузка
  через `iptables-restore`. Это исключает окно, когда соединение может оборваться
  между flush и добавлением правил. Перед применением снимается резервная копия.
"""
from __future__ import annotations

import shlex
import time
from typing import Dict, List, Tuple

from ..models import ApplyOptions, ApplyResult, ChainRules, FirewallState, NatRule, Rule
from ..ssh_client import SSHClient
from .base import CHAINS, SSHBackend

KNOWN_TARGETS = {"ACCEPT", "DROP", "REJECT"}
NAT_CHAINS = ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING")


class IptablesBackend(SSHBackend):
    id = "iptables"
    name = "iptables"
    supports_nat = True

    def __init__(self, ssh: SSHClient, variant: str = "iptables"):
        super().__init__(ssh)
        self.variant = variant  # iptables | iptables-nft (для отображения)
        self._policies: Dict[str, str] = {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"}
        self._preserved: List[str] = []   # строки таблицы filter вне управляемых цепочек
        self._custom_chain_decls: List[str] = []
        self._nat_policies: Dict[str, str] = {c: "ACCEPT" for c in NAT_CHAINS}
        self._nat_preserved: List[str] = []       # nat-строки вне PRE/POSTROUTING
        self._nat_chain_decls: List[str] = []

    # ---------- чтение ----------

    def fetch(self) -> FirewallState:
        res = self.ssh.run("iptables-save", sudo=True)
        text = res.stdout
        if not text.strip():
            return FirewallState(filter=self._fetch_via_list(), nat=[])
        return FirewallState(filter=self._parse_save(text), nat=self._parse_nat(text))

    def _fetch_via_list(self) -> ChainRules:
        cr = ChainRules()
        for ch in CHAINS:
            res = self.ssh.run(f"iptables -S {ch}", sudo=True)
            rules: List[Rule] = []
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith(f"-P {ch}"):
                    self._policies[ch] = line.split()[2]
                elif line.startswith(f"-A {ch}"):
                    rules.append(self._parse_rule_line(line))
            cr.set(ch, rules)
        return cr

    def _parse_save(self, text: str) -> ChainRules:
        cr = ChainRules()
        managed: Dict[str, List[Rule]] = {c: [] for c in CHAINS}
        self._preserved = []
        self._custom_chain_decls = []
        in_filter = False
        for raw in text.splitlines():
            line = raw.rstrip()
            if line.startswith("*"):
                in_filter = line == "*filter"
                continue
            if not in_filter or not line or line.startswith("#"):
                continue
            if line == "COMMIT":
                continue
            if line.startswith(":"):
                # объявление цепочки: ":INPUT DROP [0:0]"
                parts = line[1:].split()
                chain, policy = parts[0], parts[1]
                if chain in CHAINS:
                    self._policies[chain] = policy if policy != "-" else "ACCEPT"
                else:
                    self._custom_chain_decls.append(line)
                continue
            if line.startswith("-A "):
                chain = line.split()[1]
                if chain in CHAINS:
                    managed[chain].append(self._parse_rule_line(line))
                else:
                    self._preserved.append(line)
        for c in CHAINS:
            cr.set(c, managed[c])
        return cr

    def _parse_rule_line(self, line: str) -> Rule:
        """Разобрать строку `-A CHAIN ...` в структурированное правило.

        Понимает распространённые условия: адреса, интерфейсы (-i/-o), протокол и
        порты, состояние (-m state/-m conntrack), действие и REJECT --reject-with.
        Всё, что выходит за эти рамки, сохраняется как «сырое» (raw) и переносится
        без изменений — семантика правила при этом не искажается.
        """
        try:
            toks = shlex.split(line)
        except ValueError:
            return Rule(name="custom", raw=line, note="не разобрано")
        i, n = 2, 0
        n = len(toks)
        f = dict(src="any", dst="any", proto="any", port="", target="", note="",
                 iface_in="", iface_out="", state="", state_mod="", reject_with="")
        simple = True
        while i < n:
            t = toks[i]
            nxt = toks[i + 1] if i + 1 < n else None
            if t == "!":                       # отрицание условия — не раскладываем
                simple = False; i += 1
            elif t == "-s" and nxt is not None:
                f["src"] = nxt; i += 2
            elif t == "-d" and nxt is not None:
                f["dst"] = nxt; i += 2
            elif t == "-i" and nxt is not None:
                f["iface_in"] = nxt; i += 2
            elif t == "-o" and nxt is not None:
                f["iface_out"] = nxt; i += 2
            elif t == "-p" and nxt is not None:
                f["proto"] = nxt; i += 2
            elif t == "-m" and nxt is not None:
                if nxt in ("tcp", "udp", "icmp", "comment", "multiport", "state", "conntrack"):
                    i += 2
                else:
                    simple = False; i += 2
            elif t == "--state" and nxt is not None:
                f["state"] = nxt; f["state_mod"] = "state"; i += 2
            elif t == "--ctstate" and nxt is not None:
                f["state"] = nxt; f["state_mod"] = "conntrack"; i += 2
            elif t in ("--dport", "--dports") and nxt is not None:
                f["port"] = nxt; i += 2
            elif t == "--comment" and nxt is not None:
                f["note"] = nxt; i += 2
            elif t == "-j" and nxt is not None:
                f["target"] = nxt; i += 2
            elif t == "--reject-with" and nxt is not None:
                f["reject_with"] = nxt; i += 2
            else:
                simple = False; i += 1

        # нормализуем протокол; неизвестный протокол или порт на не-tcp/udp — в raw
        pr = f["proto"]
        if pr in ("", "any", "all", "ip", "0"):
            proto = "any"
        elif pr in ("tcp", "udp", "icmp"):
            proto = pr
        else:
            proto = "any"; simple = False
        if f["port"] and proto not in ("tcp", "udp"):
            simple = False

        if not simple or f["target"] not in KNOWN_TARGETS:
            return Rule(name=f["note"] or "custom",
                        note=f["note"] or "нестандартное правило", raw=line)
        return Rule(
            name=f["note"] or self._auto_name(f, proto),
            src=f["src"], dst=f["dst"], proto=proto, port=f["port"],
            target=f["target"], note=f["note"],
            iface_in=f["iface_in"], iface_out=f["iface_out"],
            state=f["state"], state_mod=f["state_mod"], reject_with=f["reject_with"],
            enabled=True,
        )

    @staticmethod
    def _auto_name(f: dict, proto: str) -> str:
        """Осмысленное имя для правила без комментария."""
        if f["iface_in"] == "lo" or f["iface_out"] == "lo":
            return "Loopback"
        st = f["state"].upper()
        if "ESTABLISHED" in st and f["target"] == "ACCEPT" and not f["port"]:
            return "Установленные соединения"
        if (f["target"] == "REJECT" and proto == "any"
                and f["src"] == "any" and f["dst"] == "any" and not f["state"]):
            return "Отклонить остальное"
        if proto in ("tcp", "udp") and f["port"]:
            return f"{proto}/{f['port']}"
        if proto == "icmp":
            return "ICMP"
        if f["iface_in"]:
            return f"вход {f['iface_in']}"
        return f["target"].lower()

    # ---------- генерация ----------

    def _rule_to_line(self, chain: str, r: Rule) -> str:
        if r.raw:
            return r.raw
        parts = [f"-A {chain}"]
        if r.iface_in:
            parts.append(f"-i {r.iface_in}")
        if r.iface_out:
            parts.append(f"-o {r.iface_out}")
        if r.src and r.src != "any":
            parts.append(f"-s {r.src}")
        if r.dst and r.dst != "any":
            parts.append(f"-d {r.dst}")
        if r.proto in ("tcp", "udp", "icmp"):
            parts.append(f"-p {r.proto}")
        if r.state:
            if r.state_mod == "conntrack":
                parts.append(f"-m conntrack --ctstate {r.state}")
            else:
                parts.append(f"-m state --state {r.state}")
        if r.proto in ("tcp", "udp") and r.port:
            ports = r.port.replace(" ", "")
            if "," in ports:
                parts.append(f"-m multiport --dports {ports}")
            else:
                parts.append(f"-m {r.proto} --dport {ports}")
        parts.append(f"-j {r.target}")
        if r.target == "REJECT" and r.reject_with:
            parts.append(f"--reject-with {r.reject_with}")
        if r.note:
            parts.append(f'-m comment --comment {shlex.quote(r.note)}')
        return " ".join(parts)

    def _build_filter_table(self, rules: ChainRules) -> str:
        lines = ["*filter"]
        for ch in CHAINS:
            lines.append(f":{ch} {self._policies.get(ch, 'ACCEPT')} [0:0]")
        lines.extend(self._custom_chain_decls)
        for ch in CHAINS:
            for r in rules.get(ch):
                if r.enabled:
                    lines.append(self._rule_to_line(ch, r))
        lines.extend(self._preserved)
        lines.append("COMMIT")
        return "\n".join(lines) + "\n"

    # ---------- NAT: разбор ----------

    def _parse_nat(self, text: str) -> List[NatRule]:
        self._nat_policies = {c: "ACCEPT" for c in NAT_CHAINS}
        self._nat_preserved = []
        self._nat_chain_decls = []
        rules: List[NatRule] = []
        in_nat = False
        for raw in text.splitlines():
            line = raw.rstrip()
            if line.startswith("*"):
                in_nat = line == "*nat"
                continue
            if not in_nat or not line or line.startswith("#") or line == "COMMIT":
                continue
            if line.startswith(":"):
                parts = line[1:].split()
                chain, policy = parts[0], parts[1]
                if chain in NAT_CHAINS:
                    self._nat_policies[chain] = policy if policy != "-" else "ACCEPT"
                else:
                    self._nat_chain_decls.append(line)
                continue
            if line.startswith("-A "):
                chain = line.split()[1]
                if chain in ("PREROUTING", "POSTROUTING"):
                    rules.append(self._parse_nat_line(line, chain))
                else:
                    self._nat_preserved.append(line)
        return rules

    def _parse_nat_line(self, line: str, chain: str) -> NatRule:
        raw_kind = "dnat" if chain == "PREROUTING" else "masquerade"
        try:
            toks = shlex.split(line)
        except ValueError:
            return NatRule(name="custom", kind=raw_kind, raw=line, note="не разобрано")
        i, n = 2, len(toks)
        f = dict(src="any", dst="any", proto="any", dport="", note="",
                 iface_in="", iface_out="", target="", to_source="", to_dest="")
        simple = True
        while i < n:
            t = toks[i]
            nxt = toks[i + 1] if i + 1 < n else None
            if t == "!":
                simple = False; i += 1
            elif t == "-s" and nxt is not None:
                f["src"] = nxt; i += 2
            elif t == "-d" and nxt is not None:
                f["dst"] = nxt; i += 2
            elif t == "-i" and nxt is not None:
                f["iface_in"] = nxt; i += 2
            elif t == "-o" and nxt is not None:
                f["iface_out"] = nxt; i += 2
            elif t == "-p" and nxt is not None:
                f["proto"] = nxt; i += 2
            elif t == "-m" and nxt is not None:
                if nxt in ("tcp", "udp", "comment", "multiport"):
                    i += 2
                else:
                    simple = False; i += 2
            elif t in ("--dport", "--dports") and nxt is not None:
                f["dport"] = nxt; i += 2
            elif t == "--comment" and nxt is not None:
                f["note"] = nxt; i += 2
            elif t == "-j" and nxt is not None:
                f["target"] = nxt; i += 2
            elif t == "--to-source" and nxt is not None:
                f["to_source"] = nxt; i += 2
            elif t == "--to-destination" and nxt is not None:
                f["to_dest"] = nxt; i += 2
            else:
                simple = False; i += 1

        proto = f["proto"] if f["proto"] in ("tcp", "udp") else "any"
        if f["proto"] not in ("", "any", "all", "ip", "tcp", "udp"):
            simple = False

        if f["target"] == "MASQUERADE" and chain == "POSTROUTING":
            kind = "masquerade"
        elif f["target"] == "SNAT" and f["to_source"]:
            kind = "snat"
        elif f["target"] == "DNAT" and f["to_dest"] and chain == "PREROUTING":
            kind = "dnat"
        else:
            simple = False
            kind = raw_kind

        if not simple:
            return NatRule(name=f["note"] or "custom", kind=kind, raw=line,
                           note=f["note"] or "нестандартное правило")
        return NatRule(
            name=f["note"] or self._nat_auto_name(kind, f, proto),
            kind=kind, proto=proto, src=f["src"], dst=f["dst"], dport=f["dport"],
            iface_in=f["iface_in"], iface_out=f["iface_out"],
            to_source=f["to_source"], to_dest=f["to_dest"], note=f["note"],
        )

    @staticmethod
    def _nat_auto_name(kind: str, f: dict, proto: str) -> str:
        if kind == "masquerade":
            return "Маскарадинг" + (f" {f['src']}" if f["src"] not in ("", "any") else "")
        if kind == "snat":
            return f"SNAT → {f['to_source']}"
        p = f"{proto}/{f['dport']}" if f["dport"] else "проброс"
        return f"Проброс {p} → {f['to_dest']}"

    # ---------- NAT: генерация ----------

    def _nat_to_line(self, r: NatRule) -> str:
        if r.raw:
            return r.raw
        parts = [f"-A {r.chain}"]
        if r.kind == "dnat":
            if r.iface_in:
                parts.append(f"-i {r.iface_in}")
            if r.dst and r.dst != "any":
                parts.append(f"-d {r.dst}")
            if r.proto in ("tcp", "udp"):
                parts.append(f"-p {r.proto}")
                if r.dport:
                    parts.append(f"-m {r.proto} --dport {r.dport.replace(' ', '')}")
            if r.note:
                parts.append(f'-m comment --comment {shlex.quote(r.note)}')
            parts.append(f"-j DNAT --to-destination {r.to_dest}")
        else:  # masquerade / snat, POSTROUTING
            if r.src and r.src != "any":
                parts.append(f"-s {r.src}")
            if r.iface_out:
                parts.append(f"-o {r.iface_out}")
            if r.proto in ("tcp", "udp"):
                parts.append(f"-p {r.proto}")
            if r.note:
                parts.append(f'-m comment --comment {shlex.quote(r.note)}')
            if r.kind == "snat":
                parts.append(f"-j SNAT --to-source {r.to_source}")
            else:
                parts.append("-j MASQUERADE")
        return " ".join(parts)

    def _build_nat_table(self, nat_rules: List[NatRule]) -> str:
        lines = ["*nat"]
        for ch in NAT_CHAINS:
            lines.append(f":{ch} {self._nat_policies.get(ch, 'ACCEPT')} [0:0]")
        lines.extend(self._nat_chain_decls)
        for ch in ("PREROUTING", "POSTROUTING"):
            for r in nat_rules:
                if r.enabled and r.chain == ch:
                    lines.append(self._nat_to_line(r))
        lines.extend(self._nat_preserved)
        lines.append("COMMIT")
        return "\n".join(lines) + "\n"

    # ---------- предпросмотр ----------

    def build_document(self, context: dict, state: FirewallState) -> List[str]:
        if context.get("table") == "nat":
            out = ["# iptables-restore: таблица nat будет заменена атомарно"]
            for ch in ("PREROUTING", "POSTROUTING"):
                out.append(f"# --- {ch} (политика {self._nat_policies.get(ch, 'ACCEPT')}) ---")
                any_here = False
                for r in state.nat:
                    if r.chain != ch:
                        continue
                    any_here = True
                    if not r.enabled:
                        out.append(f"# (выкл.) {r.name}")
                    else:
                        out.append("iptables -t nat " + self._nat_to_line(r))
                if not any_here:
                    out.append("#   (нет правил)")
            return out
        chain = context.get("chain", "INPUT")
        out = ["# iptables-restore: таблица filter будет заменена атомарно",
               f"# (ниже — правила цепочки {chain}; применяется весь filter целиком)",
               f"# политика по умолчанию {chain}: {self._policies.get(chain, 'ACCEPT')}"]
        for r in state.filter.get(chain):
            if not r.enabled:
                out.append(f"# (выкл.) {r.name}")
                continue
            out.append("iptables " + self._rule_to_line(chain, r))
        return out

    # ---------- применение ----------

    def apply(self, state: FirewallState, opts: ApplyOptions) -> ApplyResult:
        backup_id = None
        if opts.backup:
            backup_id = f"rubezh-{int(time.time())}"
            bpath = f"/tmp/{backup_id}.rules"
            b = self.ssh.run(f"iptables-save > {bpath}", sudo=True)
            if not b.ok:
                return ApplyResult(ok=False, message="Не удалось снять резервную копию", output=b.stderr)

        # filter и nat в одном документе — iptables-restore применит их одной транзакцией
        document = self._build_filter_table(state.filter) + self._build_nat_table(state.nat)
        cmd = f"iptables-restore <<'RUBEZH_EOF'\n{document}RUBEZH_EOF"
        res = self.ssh.run_script(cmd, sudo=True)
        if not res.ok:
            if backup_id:
                self.ssh.run(f"iptables-restore < /tmp/{backup_id}.rules", sudo=True)
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
        # netfilter-persistent, если есть; иначе прямое сохранение.
        if self.ssh.which("netfilter-persistent"):
            r = self.ssh.run("netfilter-persistent save", sudo=True)
            return "Сохранено через netfilter-persistent." if r.ok else "Сохранить не удалось."
        # типичные пути
        for path in ("/etc/iptables/rules.v4", "/etc/sysconfig/iptables"):
            check = self.ssh.run(f"test -d {shlex.quote(path.rsplit('/', 1)[0])}")
            if check.ok:
                r = self.ssh.run(f"iptables-save > {path}", sudo=True)
                return f"Сохранено в {path}." if r.ok else "Сохранить не удалось."
        return "Постоянное сохранение недоступно (нет netfilter-persistent)."
