FROM isolate-v2-demo-bastion:latest

USER root
RUN apt-get update && apt-get install -y --no-install-recommends acl zsh && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install --break-system-packages --no-cache-dir \
    'asyncssh>=2.24,<3.0' 'aiohttp>=3.12,<4.0' 'psycopg[binary]>=3.2,<4.0' 'fakeredis>=2.26,<3.0'
WORKDIR /opt/auth
CMD ["python3", "/opt/auth/tests/integration/gateway/gateway_integration.py"]
