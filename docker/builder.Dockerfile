# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang:1.25.0-bookworm
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${GO_IMAGE} AS go-runtime

FROM ${NODE_IMAGE}

COPY --from=go-runtime /usr/local/go /usr/local/go
COPY --from=go-mod-cache / /go/pkg/mod/
COPY --from=npm-cache / /opt/binaryscan/npm-cache/

ENV PATH=/usr/local/go/bin:/go/bin:$PATH \
    GOPATH=/go \
    GOTOOLCHAIN=local \
    GOPROXY=off \
    GOSUMDB=off \
    npm_config_cache=/opt/binaryscan/npm-cache \
    npm_config_offline=true \
    npm_config_audit=false \
    npm_config_fund=false

WORKDIR /seed
COPY go.mod go.sum ./
RUN --network=none go mod download && go mod verify

COPY web/package.json web/package-lock.json ./web/
RUN --network=none npm --prefix web ci --offline \
    && npm cache verify \
    && rm -rf /seed/web/node_modules /seed/web/package.json \
      /seed/web/package-lock.json /seed/go.mod /seed/go.sum

WORKDIR /src

LABEL org.opencontainers.image.title="BinaryScan offline builder" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="builder"
