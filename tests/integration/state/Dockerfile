FROM isolate-v2-demo-bastion:latest
USER root
RUN python3 -m pip install --break-system-packages --no-cache-dir \
    'psycopg[binary]>=3.2,<4.0' 'fakeredis>=2.26,<3.0'
WORKDIR /opt/auth
CMD ["python3", "/opt/auth/tests/integration/state/state_integration.py"]
