"""Абстракция фаервола: определение бэкенда, чтение и применение правил."""
from .base import FirewallBackend
from .detect import detect_backends, make_backend

__all__ = ["FirewallBackend", "detect_backends", "make_backend"]
