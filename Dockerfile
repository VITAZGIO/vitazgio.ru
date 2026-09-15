FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# В образ едет только сам сайт. Телефонное приложение (android/) сюда не
# попадает ни строкой: его собирает отдельный workflow, и в контекст
# сборки оно тоже не идёт — см. .dockerignore.
COPY app.py .
COPY static/ ./static/
COPY templates/ ./templates/

CMD ["python", "app.py"]
