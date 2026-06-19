FROM python:3.11-slim

WORKDIR /app/src/dashboard

RUN pip install --no-cache-dir fastapi uvicorn

COPY main.py index.html ./

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
