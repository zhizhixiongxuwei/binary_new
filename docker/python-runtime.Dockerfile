ARG ALPINE_IMAGE=alpine:3.22.5
FROM ${ALPINE_IMAGE}

RUN apk add --no-cache python3 \
    && addgroup -g 10001 binaryscan || true \
    && adduser -D -u 10001 -G binaryscan binaryscan || true

LABEL org.opencontainers.image.title="BinaryScan Python runtime" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.dependency-role="python-runtime"
