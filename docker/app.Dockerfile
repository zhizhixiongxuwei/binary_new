# syntax=docker/dockerfile:1.7

ARG BUILDER_IMAGE
FROM ${BUILDER_IMAGE} AS build

WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY db ./db
COPY licenses ./licenses
COPY web ./web

ENV GOTOOLCHAIN=local \
    GOPROXY=off \
    GOSUMDB=off \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    npm_config_offline=true \
    npm_config_audit=false \
    npm_config_fund=false \
    npm_config_cache=/opt/binaryscan/npm-cache

RUN --network=none go mod download
RUN --network=none npm --prefix web ci --offline
RUN --network=none npm --prefix web run build

ARG BINARYSCAN_VERSION
ARG BINARYSCAN_REVISION
ARG BINARYSCAN_SOURCE_MANIFEST_SHA256
RUN --network=none mkdir -p /out /runtime-root/data/uploads \
      /runtime-root/data/repository/.staging/uploads \
      /runtime-root/data/task-work /runtime-root/etc/binaryscan \
      /runtime-root/var/log/binaryscan \
    && go build -buildvcs=false -trimpath \
      -ldflags="-s -w -X binaryscan/internal/buildinfo.Version=${BINARYSCAN_VERSION} -X binaryscan/internal/buildinfo.Commit=${BINARYSCAN_REVISION}" \
      -o /out/binaryscan-api ./cmd/api \
    && go build -buildvcs=false -trimpath \
      -ldflags="-s -w -X binaryscan/internal/buildinfo.Version=${BINARYSCAN_VERSION} -X binaryscan/internal/buildinfo.Commit=${BINARYSCAN_REVISION}" \
      -o /out/binaryscan-maintenance ./cmd/maintenance \
    && go build -buildvcs=false -trimpath -ldflags="-s -w" \
      -o /out/binaryscan-supervisor ./cmd/supervisor \
    && go build -buildvcs=false -trimpath -ldflags="-s -w" \
      -o /out/binaryscan-web-gateway ./cmd/web-gateway

FROM scratch

ARG BINARYSCAN_VERSION
ARG BINARYSCAN_REVISION
ARG BINARYSCAN_SOURCE_MANIFEST_SHA256

COPY --from=build --chown=10001:10001 /runtime-root/ /
COPY --from=build --chown=10001:10001 /src/web/dist/ /opt/binaryscan/web/
COPY --from=build --chown=10001:10001 /src/licenses/ /usr/share/licenses/binaryscan/
COPY --from=build --chown=10001:10001 --chmod=0555 /out/binaryscan-api /usr/local/bin/binaryscan-api
COPY --from=build --chown=10001:10001 --chmod=0555 /out/binaryscan-maintenance /usr/local/bin/binaryscan-maintenance
COPY --from=build --chown=10001:10001 --chmod=0555 /out/binaryscan-supervisor /usr/local/bin/binaryscan-supervisor
COPY --from=build --chown=10001:10001 --chmod=0555 /out/binaryscan-web-gateway /usr/local/bin/binaryscan-web-gateway

USER 10001:10001
WORKDIR /app

LABEL org.opencontainers.image.title="BinaryScan app" \
      org.opencontainers.image.version="${BINARYSCAN_VERSION}" \
      org.opencontainers.image.revision="${BINARYSCAN_REVISION}" \
      com.binaryscan.source-manifest-sha256="${BINARYSCAN_SOURCE_MANIFEST_SHA256}" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="app"

ENTRYPOINT ["/usr/local/bin/binaryscan-supervisor"]
CMD ["app"]
