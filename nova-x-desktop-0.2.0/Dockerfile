FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=7860 \
    NOVA_DATA_DIR=/data/nova \
    NOVA_WORKSPACE_DIR=/data/nova/workspace

WORKDIR /app
RUN useradd --create-home --uid 1000 nova \
    && mkdir -p /data/nova /data/nova/workspace \
    && chown -R nova:nova /data /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=nova:nova . .

USER nova
EXPOSE 7860
CMD ["sh", "-c", "uvicorn nova.main:app --host 0.0.0.0 --port ${PORT:-7860} --workers 1"]
