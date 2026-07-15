FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
# --no-cache-dir keeps the image lean; perl-base is removed because it is not
# needed by a Python runtime and carries CVEs with no upstream fix available.
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get update \
    && apt-get purge -y --allow-remove-essential perl perl-base \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY app.py .

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Intentionally runs as root — Falco detects privileged shell execs into this container.
# In a production image, add: RUN useradd -m app && USER app
CMD ["python", "app.py"]
