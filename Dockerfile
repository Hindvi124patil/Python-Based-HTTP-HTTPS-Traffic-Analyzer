
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads outputs

ENV PYTHONUNBUFFERED=1
ENV PORT=10000

EXPOSE 10000
COPY NetScope_HTTP_HTTPS_Analyzer/templates ./templates
COPY NetScope_HTTP_HTTPS_Analyzer/static ./static
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "app:app"]
