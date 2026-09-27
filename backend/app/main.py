"""Точка входа FastAPI: API + раздача фронтенда."""
from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api import router

_HERE = os.path.dirname(os.path.abspath(__file__))
_FRONTEND = os.path.abspath(os.path.join(_HERE, "..", "..", "frontend"))

app = FastAPI(title="Рубеж — Firewall GUI", version=__version__)
app.include_router(router)


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": __version__}


# Статика фронтенда. index.html отдаём на корне, остальное — как файлы.
if os.path.isdir(_FRONTEND):
    @app.get("/")
    def index():
        return FileResponse(os.path.join(_FRONTEND, "index.html"))

    app.mount("/", StaticFiles(directory=_FRONTEND, html=True), name="frontend")
