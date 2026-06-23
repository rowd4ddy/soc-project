FROM python:3.11-slim

WORKDIR /app/src/dashboard

ENV PYTHONDONTWRITEBYTECODE=1

RUN pip install --no-cache-dir fastapi uvicorn pydantic "chromadb==0.5.5"

COPY main.py index.html ./

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]