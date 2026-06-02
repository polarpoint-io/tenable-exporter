FROM python:3.12-slim

# VERSION is injected by @codedependant/semantic-release-docker at release time
# (e.g. "1.2.3"). When empty or unset (snapshot / local builds), the package is
# installed directly from the local source tree instead.
ARG VERSION=

WORKDIR /app

COPY pyproject.toml exporter.py ./

RUN pip install --no-cache-dir --upgrade pip && \
    if [ -n "$VERSION" ]; then \
        echo "Installing tenable-exporter==${VERSION} from PyPI" && \
        pip install --no-cache-dir "tenable-exporter==${VERSION}"; \
    else \
        echo "Installing from local source (snapshot build)" && \
        pip install --no-cache-dir -e .; \
    fi

ENV EXPORTER_PORT=9190 \
    SCRAPE_INTERVAL=300

EXPOSE 9190

CMD ["tenable-exporter"]
