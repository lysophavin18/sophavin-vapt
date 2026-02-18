FROM python:3.11-slim

LABEL maintainer="Noovastack-VAPT"
LABEL description="GraphQLmap - GraphQL Penetration Testing Tool"

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone GraphQLmap
WORKDIR /opt
RUN git clone https://github.com/swisskyrepo/GraphQLmap.git

WORKDIR /opt/GraphQLmap
RUN pip install --no-cache-dir -r requirements.txt

# Create output directory
RUN mkdir -p /results

# Set entrypoint
ENTRYPOINT ["python3", "graphqlmap.py"]
