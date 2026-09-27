"""SSH-клиент поверх paramiko с поддержкой sudo.

Инкапсулирует одно подключение к серверу и выполнение команд, при необходимости
через `sudo`. Пароль sudo передаётся в stdin команды `sudo -S`, поэтому не
светится в списке процессов.
"""
from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from typing import Optional

try:
    import paramiko
except ImportError:  # позволяем импортировать модуль без paramiko (демо-режим)
    paramiko = None  # type: ignore

from .models import Connection


class SSHError(Exception):
    pass


@dataclass
class CommandResult:
    code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.code == 0


class SSHClient:
    """Тонкая обёртка над paramiko.SSHClient под нужды приложения."""

    def __init__(self, conn: Connection):
        if paramiko is None:
            raise SSHError("Библиотека paramiko не установлена. Выполните: pip install paramiko")
        self.conn = conn
        self._client: Optional["paramiko.SSHClient"] = None

    # ---------- жизненный цикл ----------

    def connect(self, timeout: float = 12.0) -> None:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(
            hostname=self.conn.host,
            port=self.conn.port,
            username=self.conn.username,
            timeout=timeout,
            allow_agent=True,
            look_for_keys=False,
        )
        try:
            if self.conn.auth == "key":
                key_path = os.path.expanduser(self.conn.key_path)
                if not os.path.exists(key_path):
                    raise SSHError(f"Файл ключа не найден: {key_path}")
                kwargs["key_filename"] = key_path
                kwargs["look_for_keys"] = True
            else:
                kwargs["password"] = self.conn.password
            c.connect(**kwargs)
        except SSHError:
            raise
        except paramiko.AuthenticationException:
            raise SSHError("Ошибка аутентификации: проверьте пользователя, ключ или пароль.")
        except Exception as e:  # noqa: BLE001
            raise SSHError(f"Не удалось подключиться к {self.conn.host}:{self.conn.port} — {e}")
        self._client = c

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> "SSHClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------- выполнение команд ----------

    def run(self, command: str, sudo: bool = False, timeout: float = 30.0) -> CommandResult:
        if not self._client:
            raise SSHError("Нет активного подключения.")

        if sudo and self.conn.use_sudo:
            if self.conn.sudo_password:
                # -S читает пароль из stdin, -p '' убирает подсказку
                command = f"sudo -S -p '' {command}"
            else:
                command = f"sudo -n {command}"  # NOPASSWD

        stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        if sudo and self.conn.use_sudo and self.conn.sudo_password:
            stdin.write(self.conn.sudo_password + "\n")
            stdin.flush()
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        return CommandResult(code=code, stdout=out, stderr=err)

    def run_script(self, script: str, sudo: bool = False, timeout: float = 60.0) -> CommandResult:
        """Выполнить многострочный скрипт через `bash -c`."""
        return self.run(f"bash -c {shlex.quote(script)}", sudo=sudo, timeout=timeout)

    def which(self, binary: str) -> Optional[str]:
        res = self.run(f"command -v {shlex.quote(binary)}")
        path = res.stdout.strip()
        return path or None

    def check_sudo(self) -> bool:
        """Проверить, что sudo доступен (в т.ч. с паролем)."""
        if not self.conn.use_sudo:
            return True
        res = self.run("id -u", sudo=True)
        return res.ok and res.stdout.strip() == "0"
