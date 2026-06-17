FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Your source code is mounted as a volume (see docker-compose.yml)
# so you don't need to rebuild the image every time you change code

CMD ["python", "-u", "src/main.py"]