FROM perl:slim
RUN apt-get update && apt-get install -y git && \
    git clone --depth 1 https://github.com/sullo/nikto.git /nikto && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["perl", "/nikto/program/nikto.pl"]
