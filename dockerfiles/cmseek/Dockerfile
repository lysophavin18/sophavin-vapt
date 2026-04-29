FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && git clone --depth=1 https://github.com/Tuhinshubhra/CMSeeK.git /opt/cmseek \
    && pip install --no-cache-dir requests \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /results

WORKDIR /opt/cmseek

CMD ["tail", "-f", "/dev/null"]
