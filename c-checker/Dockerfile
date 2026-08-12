ARG C_CHECKER_BUILDER_IMAGE=binaryscan/c-checker-builder:0.1.0
ARG C_CHECKER_JRE_IMAGE=eclipse-temurin:17-jre-jammy
ARG BINARYSCAN_VERSION=0.1.0
ARG REVISION=unknown
ARG SOURCE_MANIFEST_SHA256=unknown
ARG BINARYSCAN_REVISION=${REVISION}
ARG BINARYSCAN_SOURCE_MANIFEST_SHA256=${SOURCE_MANIFEST_SHA256}

FROM ${C_CHECKER_BUILDER_IMAGE} AS build
WORKDIR /opt/binaryscan/c-checker-build
COPY pom.xml ./
COPY src ./src
RUN --network=none mvn -B -o -DskipTests package

FROM ${C_CHECKER_JRE_IMAGE}
ARG BINARYSCAN_VERSION
ARG REVISION
ARG SOURCE_MANIFEST_SHA256
ARG BINARYSCAN_REVISION
ARG BINARYSCAN_SOURCE_MANIFEST_SHA256
WORKDIR /opt/binaryscan/c-checker

LABEL org.opencontainers.image.title="BinaryScan C Checker" \
      org.opencontainers.image.version="${BINARYSCAN_VERSION}" \
      org.opencontainers.image.revision="${BINARYSCAN_REVISION}" \
      com.binaryscan.component="c-checker" \
      com.binaryscan.source-manifest-sha256="${BINARYSCAN_SOURCE_MANIFEST_SHA256}" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="c-checker"

COPY --from=build /opt/binaryscan/c-checker-build/target/c-checker.jar ./c-checker.jar
COPY docker/c-checker-healthcheck /opt/binaryscan/bin/c-checker-healthcheck
COPY NOTICE.md ./NOTICE.md
COPY vendor/antlr-grammars-v4/LICENSE-C-GRAMMAR.txt ./licenses/antlr-c-grammar-BSD.txt

RUN chmod 0555 /opt/binaryscan/bin/c-checker-healthcheck \
        /opt/binaryscan/c-checker \
        /opt/binaryscan/c-checker/licenses \
    && chmod 0444 /opt/binaryscan/c-checker/c-checker.jar \
        /opt/binaryscan/c-checker/NOTICE.md \
        /opt/binaryscan/c-checker/licenses/antlr-c-grammar-BSD.txt \
    && chown -R 10001:10001 /opt/binaryscan/c-checker /opt/binaryscan/bin/c-checker-healthcheck

USER 10001:10001
EXPOSE 8080
ENV HOME=/tmp \
    TMPDIR=/tmp \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=/tmp -XX:MaxRAMPercentage=75.0"
ENTRYPOINT ["java", "-jar", "/opt/binaryscan/c-checker/c-checker.jar"]
