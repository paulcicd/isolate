FROM python:3.12-slim

WORKDIR /opt/isolate

RUN pip install --no-cache-dir "redis>=5.0.0"

COPY shared /opt/isolate/shared
COPY tests/integration/backup/backup_roundtrip.py /opt/isolate/backup_roundtrip.py

CMD ["python", "/opt/isolate/backup_roundtrip.py"]
