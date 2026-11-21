# Multi-arch build (needs Docker with buildx):
#   docker buildx build --platform linux/arm64 -t vartadns:latest \
#     --output type=docker,dest=vartadns-arm64.tar .
# Supported platforms: linux/amd64, linux/arm64, linux/arm/v7
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT VERSION=dev
WORKDIR /src
COPY . .
# Pure Go, no cgo: one static binary for any architecture.
RUN GOARM=${TARGETVARIANT#v} CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X github.com/takobas/vartadns/internal/app.Version=${VERSION}" \
    -o /out/vartadns ./cmd/vartadns
RUN apk add --no-cache ca-certificates && mkdir -p /out/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/vartadns /vartadns
COPY --from=build /out/data /data
COPY deploy/config.json /etc/vartadns/config.json
ENV VARTA_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 53/udp 53/tcp 8080/tcp
ENTRYPOINT ["/vartadns", "-config", "/etc/vartadns/config.json"]
