# python:3.9 is the newest base on which the intentionally-old, vulnerable deps
# still import: Werkzeug 0.14.1 uses collections.Container/Iterable/MutableSet,
# which Python 3.10+ removed. On 3.11 the app crashes on import (never boots),
# so Falco has no running items-api to watch. Keep the deps (they carry the
# intentional CVEs that hold the Trivy gate red); pin the base to 3.9 so it runs.
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
# Install app deps, then strip build-time tools (wheel, jaraco.context) and
# perl-base from the runtime image — none are needed once pip install completes.
RUN pip install --no-cache-dir -r requirements.txt \
    && pip uninstall -y wheel jaraco.context jaraco.functools \
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
