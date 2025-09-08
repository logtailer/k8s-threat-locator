FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
# --no-cache-dir keeps the image lean
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

CMD ["python", "app.py"]
