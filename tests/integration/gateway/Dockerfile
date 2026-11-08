FROM isolate-v2-demo-bastion:latest

USER root
RUN apt-get update && apt-get install -y --no-install-recommends acl zsh && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements-dev.txt /tmp/isolate-requirements/
RUN python3 -m pip install --break-system-packages --no-cache-dir -r /tmp/isolate-requirements/requirements-dev.txt
WORKDIR /opt/auth
CMD ["python3", "/opt/auth/tests/integration/gateway/gateway_integration.py"]
