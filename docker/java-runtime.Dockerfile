# syntax=docker/dockerfile:1.7

ARG SOURCE_IMAGE
FROM ${SOURCE_IMAGE} AS cleaned-runtime

USER root
RUN rm -f /usr/local/bin/binaryscan-worker \
      /usr/local/bin/binaryscan-bytecode-tool \
    && rm -rf /opt/binaryscan

FROM scratch
COPY --from=cleaned-runtime / /

ENV PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    JAVA_HOME=/opt/java/openjdk \
    HOME=/tmp \
    TMPDIR=/tmp \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

USER 10001:10001
WORKDIR /app

LABEL org.opencontainers.image.title="BinaryScan Java tool runtime" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="java-base"

ENTRYPOINT []
CMD ["/opt/java/openjdk/bin/java", "-version"]
