# Рубеж — образ приложения (FastAPI + фронтенд)
FROM python:3.12-slim

# Не создавать .pyc, не буферизовать вывод
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RUBEZH_DATA=/data

WORKDIR /app

# Зависимости — отдельным слоем для кеширования
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Код приложения
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Каталог для настроек и правил (монтируется как volume)
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8555
WORKDIR /app/backend

# Проверка живости
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8555/healthz',timeout=3).status==200 else 1)"

CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8555"]
