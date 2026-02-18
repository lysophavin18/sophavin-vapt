FROM python:3.11-slim

LABEL maintainer="Noovastack-VAPT"
LABEL description="JWT_Tool - JWT Analysis and Attack Tool"

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone jwt_tool
WORKDIR /opt
RUN git clone https://github.com/ticarpi/jwt_tool.git

WORKDIR /opt/jwt_tool
RUN pip install --no-cache-dir -r requirements.txt

# Create output directory
RUN mkdir -p /results

# Set entrypoint
ENTRYPOINT ["python3", "jwt_tool.py"]
