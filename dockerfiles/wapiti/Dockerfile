FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libxml2-dev \
    libxslt-dev \
    libssl-dev \
    && pip install --no-cache-dir wapiti3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /results

WORKDIR /results

CMD ["tail", "-f", "/dev/null"]
