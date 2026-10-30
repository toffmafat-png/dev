FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NOVA_HOST=127.0.0.1 \
    NOVA_PORT=8000 \
    NOVA_DATA_DIR=/home/nova/.local/share/nova-x \
    NOVA_WORKSPACE_DIR=/home/nova/workspace

WORKDIR /app

RUN useradd -m -u 1000 nova && mkdir -p /home/nova/.local/share/nova-x /home/nova/workspace && chown -R nova:nova /home/nova /app

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

COPY --chown=nova:nova . /app

USER nova
EXPOSE 8000

CMD ["uvicorn", "nova.main:app", "--host", "127.0.0.1", "--port", "8000"]
