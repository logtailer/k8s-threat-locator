FROM python:3.9.18-slim

WORKDIR /app

COPY requirements.txt .
# --no-cache-dir keeps the image lean
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Intentionally runs as root — Falco detects privileged shell execs into this container.
# In a production image, add: RUN useradd -m app && USER app
CMD ["python", "app.py"]
