# Starfly Fabrics — Server Dockerfile
# Multi-stage build for minimal production image.

# ── BUILD STAGE ────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS=linux
ARG TARGETARCH

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -tags dev \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o /starfly ./cmd/starfly/

# ── RUNTIME STAGE ──────────────────────────────────────────────────
# Alpine chosen over distroless: the binary alone is ~70MB (14 credential
# validators, embedded NATS, OPA, badger, Temporal SDK). Alpine adds ~13MB
# for ca-certificates, tzdata, wget (used by HEALTHCHECK), and a shell for
# debugging. Distroless would save ~8MB but loses the wget healthcheck and
# any ability to exec into the container for troubleshooting. Acceptable
# trade-off at 83MB total. See FORGE-006.
FROM alpine:3.21

LABEL org.opencontainers.image.source="https://github.com/starfly-fabrics/starfly"
LABEL org.opencontainers.image.vendor="starfly-fabrics"
LABEL org.opencontainers.image.title="starfly"
LABEL org.opencontainers.image.description="Kubernetes-native NHI identity broker"

RUN apk add --no-cache ca-certificates tzdata wget \
    && addgroup -S starfly && adduser -S starfly -G starfly \
    && mkdir -p /data/starfly /data/nats /tmp/nats \
    && chown -R starfly:starfly /data/starfly /data/nats /tmp/nats

COPY --from=builder /starfly /usr/local/bin/starfly

USER starfly:starfly

EXPOSE 8693 8694

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8693/v1/sys/health"]

ENTRYPOINT ["starfly"]
