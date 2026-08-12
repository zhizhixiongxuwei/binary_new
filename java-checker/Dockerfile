ARG JAVA_CHECKER_BUILDER_IMAGE=binaryscan/java-checker-builder:0.1.0
ARG JAVA_CHECKER_JRE_IMAGE=eclipse-temurin:17-jre-jammy
ARG BINARYSCAN_VERSION=0.1.0
ARG REVISION=unknown
ARG SOURCE_MANIFEST_SHA256=unknown
ARG BINARYSCAN_REVISION=${REVISION}
ARG BINARYSCAN_SOURCE_MANIFEST_SHA256=${SOURCE_MANIFEST_SHA256}

FROM ${JAVA_CHECKER_BUILDER_IMAGE} AS build
WORKDIR /opt/binaryscan/java-checker-build
COPY pom.xml ./
COPY src ./src
RUN --network=none mvn -B -o -DskipTests package

FROM ${JAVA_CHECKER_JRE_IMAGE}
ARG BINARYSCAN_VERSION
ARG REVISION
ARG SOURCE_MANIFEST_SHA256
ARG BINARYSCAN_REVISION
ARG BINARYSCAN_SOURCE_MANIFEST_SHA256
WORKDIR /opt/binaryscan/java-checker

LABEL org.opencontainers.image.title="BinaryScan Java Checker" \
      org.opencontainers.image.version="${BINARYSCAN_VERSION}" \
      org.opencontainers.image.revision="${BINARYSCAN_REVISION}" \
      com.binaryscan.component="java-checker" \
      com.binaryscan.source-manifest-sha256="${BINARYSCAN_SOURCE_MANIFEST_SHA256}" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="java-checker"

COPY --from=build /opt/binaryscan/java-checker-build/target/java-checker.jar ./java-checker.jar
COPY docker/java-checker-healthcheck /opt/binaryscan/bin/java-checker-healthcheck
COPY NOTICE.md ./NOTICE.md

RUN chmod 0555 /opt/binaryscan/bin/java-checker-healthcheck \
        /opt/binaryscan/java-checker \
    && chmod 0444 /opt/binaryscan/java-checker/java-checker.jar \
        /opt/binaryscan/java-checker/NOTICE.md \
    && chown -R 10001:10001 /opt/binaryscan/java-checker /opt/binaryscan/bin/java-checker-healthcheck

USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
ENV HOME=/tmp \
    TMPDIR=/tmp \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=/tmp -Xms64m -Xmx384m -XX:+ExitOnOutOfMemoryError"
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=6 \
    CMD ["/opt/binaryscan/bin/java-checker-healthcheck"]
ENTRYPOINT ["java", "-jar", "/opt/binaryscan/java-checker/java-checker.jar"]
