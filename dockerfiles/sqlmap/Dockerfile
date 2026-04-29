FROM python:3.11-slim
RUN apt-get update && apt-get install -y git && \
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /sqlmap && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["python3", "/sqlmap/sqlmap.py"]
