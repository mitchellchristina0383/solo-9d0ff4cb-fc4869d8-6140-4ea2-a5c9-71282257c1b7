FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY dnslab ./dnslab

# 8000/tcp = HTTP API + /docs, 5353/udp = DNS (slave)
EXPOSE 8000 5353/udp

# Default to the master; the slave overrides this in docker-compose.yml.
CMD ["uvicorn", "dnslab.master_app:app", "--host", "0.0.0.0", "--port", "8000"]
