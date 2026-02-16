FROM python:3.10-slim

RUN useradd -m -u 1000 fidsapp

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R fidsapp:fidsapp /app && \
    chmod 755 /app && \
    chmod 644 /app/*.py || true && \
    mkdir -p /app/data && \
    chown -R fidsapp:fidsapp /app/data

USER fidsapp

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health')" || exit 1

CMD ["sh", "-c", "python init_db.py && python app.py"]