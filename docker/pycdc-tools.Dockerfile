ARG ALPINE_IMAGE=alpine:3.22.5
FROM ${ALPINE_IMAGE}

COPY pycdc /opt/bytecode-tools/pycdc/pycdc
RUN mkdir -p /opt/bytecode-tools/pycdc \
    && chmod 0555 /opt/bytecode-tools/pycdc/pycdc

LABEL org.opencontainers.image.title="BinaryScan pycdc tools" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.dependency-role="pycdc-tools" \
      com.binaryscan.pycdc-version="1.1.1"
