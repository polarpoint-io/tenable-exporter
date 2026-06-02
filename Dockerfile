FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY exporter.py .

RUN pip install --no-cache-dir -e .

ENV EXPORTER_PORT=9190
ENV SCRAPE_INTERVAL=300

EXPOSE 9190

CMD ["tenable-exporter"]
