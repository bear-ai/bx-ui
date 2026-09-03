# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.24
ARG DEBIAN_VERSION=bookworm-slim
ARG XRAY_VERSION=v26.3.27

FROM golang:${GO_VERSION}-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/x-ui .

FROM debian:${DEBIAN_VERSION} AS xray
ARG TARGETARCH
ARG XRAY_VERSION
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && case "${TARGETARCH}" in \
        amd64) xray_asset="Xray-linux-64.zip" ;; \
        arm64) xray_asset="Xray-linux-arm64-v8a.zip" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -fsSLo /tmp/xray.zip \
        "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${xray_asset}" \
    && mkdir -p /out/bin \
    && unzip -jq /tmp/xray.zip xray geoip.dat geosite.dat -d /out/bin \
    && mv /out/bin/xray "/out/bin/xray-linux-${TARGETARCH}" \
    && chmod 755 "/out/bin/xray-linux-${TARGETARCH}"

FROM debian:${DEBIAN_VERSION}
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
WORKDIR /usr/local/x-ui
COPY --from=builder /out/x-ui ./x-ui
COPY --from=xray /out/bin ./bin
VOLUME ["/etc/x-ui", "/root/cert"]
EXPOSE 54321
ENTRYPOINT ["./x-ui"]
