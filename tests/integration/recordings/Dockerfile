FROM isolate-gateway-tests:local
RUN python3 -m pip install --break-system-packages --no-cache-dir 'boto3>=1.40,<2'
WORKDIR /opt/auth
CMD ["python3", "/opt/auth/tests/integration/recordings/recordings_integration.py"]
