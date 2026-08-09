# syntax=docker/dockerfile:1.7

ARG TRIVY_IMAGE=aquasec/trivy:0.72.0
FROM ${TRIVY_IMAGE} AS trivy-runtime

FROM alpine:3.20 AS sealed-cache
ARG TRIVY_DB_ID
ARG TRIVY_JAVA_DB_ID

COPY bundle.json /opt/trivy-cache/bundle.json
COPY --from=trivy-db . /opt/trivy-cache/db/versions/${TRIVY_DB_ID}/
COPY --from=trivy-java-db . /opt/trivy-cache/java-db/versions/${TRIVY_JAVA_DB_ID}/
RUN find /opt/trivy-cache -type d -exec chmod 0555 {} + \
    && find /opt/trivy-cache -type f -exec chmod 0444 {} +

FROM scratch
COPY --from=trivy-runtime --chmod=0555 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=sealed-cache --chown=10001:10001 /opt/trivy-cache /opt/trivy-cache

ENV HOME=/tmp \
    TMPDIR=/tmp \
    TRIVY_DISABLE_TELEMETRY=true \
    TRIVY_OFFLINE_SCAN=true \
    TRIVY_SKIP_DB_UPDATE=true \
    TRIVY_SKIP_JAVA_DB_UPDATE=true \
    TRIVY_SKIP_VERSION_CHECK=true

USER 10001:10001
WORKDIR /app

LABEL org.opencontainers.image.title="BinaryScan Trivy offline runtime" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="trivy-base"

ENTRYPOINT ["/usr/local/bin/trivy"]
CMD ["version", "--format", "json"]
