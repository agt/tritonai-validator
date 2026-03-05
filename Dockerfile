FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer cached separately from source)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app/ ./app/

# Non-root user for security
RUN useradd -r -u 1000 webhook
USER 1000

EXPOSE 8443

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8443", \
     "--ssl-keyfile", "/tls/tls.key", \
     "--ssl-certfile", "/tls/tls.crt"]
