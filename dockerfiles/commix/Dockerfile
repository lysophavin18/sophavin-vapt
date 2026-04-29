FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && git clone --depth=1 https://github.com/commixproject/commix.git /opt/commix \
    && pip install --no-cache-dir requests \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /results

WORKDIR /opt/commix

CMD ["tail", "-f", "/dev/null"]
