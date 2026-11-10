FROM isolate-gateway-integration-runner:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client mariadb-client \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install --break-system-packages --no-cache-dir 'mysql-connector-python>=9,<10'
WORKDIR /opt/auth
CMD ["python3", "/opt/auth/tests/integration/databases/database_integration.py"]
