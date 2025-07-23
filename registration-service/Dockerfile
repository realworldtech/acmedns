FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY registration-service.py .

# Create data directory
RUN mkdir -p /data && chown -R 1000:1000 /data

# Run as non-root user
USER 1000:1000

EXPOSE 5000

CMD ["python", "registration-service.py"]