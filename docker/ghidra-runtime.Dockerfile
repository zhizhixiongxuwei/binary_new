# syntax=docker/dockerfile:1.7

ARG SOURCE_IMAGE
FROM ${SOURCE_IMAGE} AS cleaned-runtime

USER root
RUN rm -f /usr/local/bin/binaryscan-worker \
    && rm -rf /opt/binaryscan

FROM scratch
COPY --from=cleaned-runtime / /

ENV PATH=/opt/java/openjdk/bin:/usr/local/bin:/usr/bin:/bin \
    JAVA_HOME=/opt/java/openjdk \
    HOME=/tmp \
    TMPDIR=/tmp

USER 10001:10001
WORKDIR /app

LABEL org.opencontainers.image.title="BinaryScan Ghidra runtime" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="ghidra-base"

ENTRYPOINT []
CMD ["/opt/java/openjdk/bin/java", "-version"]
