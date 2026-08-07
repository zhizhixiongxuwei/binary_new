# syntax=docker/dockerfile:1.7

ARG BUILDER_IMAGE
ARG TRIVY_RUNTIME_DB_IMAGE

FROM ${BUILDER_IMAGE} AS build
WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY db ./db
ENV GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN --network=none go mod download
ARG BINARYSCAN_VERSION
ARG BINARYSCAN_REVISION
ARG BINARYSCAN_SOURCE_MANIFEST_SHA256
RUN --network=none go build -buildvcs=false -trimpath \
      -ldflags="-s -w -X binaryscan/internal/buildinfo.Version=${BINARYSCAN_VERSION} -X binaryscan/internal/buildinfo.Commit=${BINARYSCAN_REVISION}" \
      -o /out/binaryscan-worker ./cmd/worker \
	&& go build -buildvcs=false -trimpath -ldflags="-s -w" \
	  -o /out/binaryscan-bundle-check ./cmd/bundle-check \
	&& go build -buildvcs=false -trimpath -ldflags="-s -w" \
      -o /out/binaryscan-supervisor ./cmd/supervisor

FROM ${TRIVY_RUNTIME_DB_IMAGE}
ARG BINARYSCAN_VERSION
ARG BINARYSCAN_REVISION
ARG BINARYSCAN_SOURCE_MANIFEST_SHA256
USER root
COPY --from=build --chmod=0555 /out/binaryscan-worker /usr/local/bin/binaryscan-worker
COPY --from=build --chmod=0555 /out/binaryscan-bundle-check /usr/local/bin/binaryscan-bundle-check
COPY --from=build --chmod=0555 /out/binaryscan-supervisor /usr/local/bin/binaryscan-supervisor
COPY --chown=10001:10001 licenses/ /usr/share/licenses/binaryscan/
ENV HOME=/tmp \
    TMPDIR=/tmp \
    TRIVY_DISABLE_TELEMETRY=true \
    TRIVY_OFFLINE_SCAN=true \
    TRIVY_SKIP_DB_UPDATE=true \
    TRIVY_SKIP_JAVA_DB_UPDATE=true \
    TRIVY_SKIP_VERSION_CHECK=true
USER 10001:10001
WORKDIR /app
LABEL org.opencontainers.image.title="BinaryScan scanner" \
      org.opencontainers.image.version="${BINARYSCAN_VERSION}" \
      org.opencontainers.image.revision="${BINARYSCAN_REVISION}" \
      com.binaryscan.source-manifest-sha256="${BINARYSCAN_SOURCE_MANIFEST_SHA256}" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="scanner"
ENTRYPOINT ["/usr/local/bin/binaryscan-supervisor"]
CMD ["scanner"]
