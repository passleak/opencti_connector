FROM python:3.11-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-connector-passleak

RUN apk --no-cache add git build-base libmagic && \
    cd /opt/opencti-connector-passleak && \
    pip3 install --no-cache-dir -r requirements.txt && \
    pip3 install --no-cache-dir pytest && \
    apk del git build-base

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
