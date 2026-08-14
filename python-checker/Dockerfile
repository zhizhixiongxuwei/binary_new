# syntax=docker/dockerfile:1.7

ARG PYTHON_RUNTIME_IMAGE=binaryscan/python-runtime:3.12-alpine-v1

FROM ${PYTHON_RUNTIME_IMAGE}
ARG BINARYSCAN_VERSION=0.1.0
ARG BINARYSCAN_REVISION=unknown
ARG BINARYSCAN_SOURCE_MANIFEST_SHA256=unknown
WORKDIR /opt/binaryscan/python-checker

LABEL org.opencontainers.image.title="BinaryScan Python Checker" \
      org.opencontainers.image.version="${BINARYSCAN_VERSION}" \
      org.opencontainers.image.revision="${BINARYSCAN_REVISION}" \
      com.binaryscan.component="python-checker" \
      com.binaryscan.source-manifest-sha256="${BINARYSCAN_SOURCE_MANIFEST_SHA256}" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="python-checker"

COPY checker.py ./checker.py
COPY rules.py ./rules.py
COPY healthcheck.py ./healthcheck.py
COPY NOTICE.md ./NOTICE.md

RUN chmod 0555 /opt/binaryscan/python-checker \
        /opt/binaryscan/python-checker/checker.py \
        /opt/binaryscan/python-checker/rules.py \
        /opt/binaryscan/python-checker/healthcheck.py \
    && chmod 0444 /opt/binaryscan/python-checker/NOTICE.md

USER 10001:10001
ENV HOME=/tmp TMPDIR=/tmp PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python3", "/opt/binaryscan/python-checker/healthcheck.py", "http://127.0.0.1:8080"]
ENTRYPOINT ["python3", "/opt/binaryscan/python-checker/checker.py"]
CMD ["8080"]
