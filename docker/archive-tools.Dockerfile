# syntax=docker/dockerfile:1.7

ARG ALPINE_IMAGE=alpine:3.22.5
FROM ${ALPINE_IMAGE}

ARG FILE_PACKAGE_VERSION=5.46-r2
ARG LIBARCHIVE_TOOLS_PACKAGE_VERSION=3.8.3-r0
ARG SEVEN_ZIP_PACKAGE_VERSION=24.09-r0

RUN apk add --no-cache \
      "file=${FILE_PACKAGE_VERSION}" \
      "libarchive-tools=${LIBARCHIVE_TOOLS_PACKAGE_VERSION}" \
      "7zip=${SEVEN_ZIP_PACKAGE_VERSION}" \
    && test "$(apk info -e file)" = file \
    && test "$(apk info -e libarchive-tools)" = libarchive-tools \
    && test "$(apk info -e 7zip)" = 7zip \
    && file --version 2>&1 | grep -F 'file-5.46' >/dev/null \
    && bsdtar --version 2>&1 | grep -F 'libarchive 3.8.3' >/dev/null \
    && 7zz -h 2>&1 | grep -F '24.09' >/dev/null \
    && rm -rf /var/cache/apk/*

USER 10001:10001
WORKDIR /app

LABEL org.opencontainers.image.title="BinaryScan archive tools" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.dependency-role="archive-tools" \
      com.binaryscan.archive-file-version="5.46" \
      com.binaryscan.archive-libarchive-version="3.8.3" \
      com.binaryscan.archive-7zip-version="24.09"
