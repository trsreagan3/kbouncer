# syntax=docker/dockerfile:1.7
#
# kbounce — local Kubernetes API-call gating proxy.
#
# Multi-stage build:
#   1. golang:1.26-alpine builds a static CGO-free binary with version
#      stamping via -ldflags. Matches go.mod's `go 1.26.0` directive so
#      the toolchain doesn't have to auto-download.
#   2. gcr.io/distroless/static-debian12:nonroot runs the binary as a
#      non-root user with no shell, no package manager, ~2MB base.
#
# Image is a packaging CONVENIENCE — same binary as `go install` /
# `brew install kbounce`, no extra features, no telemetry. The
# version-check subcommand only contacts the network when an operator
# runs `kbounce version-check` explicitly. See [[ibounce-honest-positioning]].

# ---- builder ---------------------------------------------------------------
FROM golang:1.26-alpine AS builder

# git is needed for `go build` to read VCS info when --buildvcs=auto fires,
# and for the version-stamping `git describe` we invoke before COPY.
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

# Source.
COPY . .

# Stamp version from build arg (passed in by CI from `git describe`);
# fall back to "docker" when built locally without --build-arg VERSION=...
ARG VERSION=docker
ARG COMMIT=none
ARG BUILD_TIME=unknown

# Predefined by BuildKit per the --platform flag; declared here without
# defaults so BuildKit's auto-population isn't masked. With Docker 28.x +
# BuildKit v0.24 a default value on these specific ARGs WINS over the
# auto-populated value, silently producing wrong-arch binaries (e.g.
# --platform linux/arm64 emitting GOARCH=amd64). See docker/docs#5077
# and the local reproducer + CI log noted in commit fixing #246.
ARG TARGETOS
ARG TARGETARCH

# Static binary: CGO_ENABLED=0 + -trimpath + -s -w for size + ldflags
# to populate the version/commit/buildTime vars in internal/cli/cli.go.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
        -trimpath \
        -ldflags "-s -w \
            -X github.com/trsreagan3/kbouncer/internal/cli.version=${VERSION} \
            -X github.com/trsreagan3/kbouncer/internal/cli.commit=${COMMIT} \
            -X github.com/trsreagan3/kbouncer/internal/cli.buildTime=${BUILD_TIME}" \
        -o /out/kbounce \
        ./cmd/kbounce

# ---- runtime ---------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# OCI metadata — surfaced on GHCR + by `docker inspect`.
LABEL org.opencontainers.image.source="https://github.com/trsreagan3/kbouncer" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="kbounce" \
      org.opencontainers.image.description="Kubernetes safety proxy for AI agents and dev workflows"

COPY --from=builder /out/kbounce /usr/local/bin/kbounce

# Document the default proxy port. The binary refuses non-loopback binds
# without --i-know-this-binds-externally, so EXPOSE here is purely
# documentation — the operator still has to pass --host 0.0.0.0 +
# the acknowledgement flag for the port to be reachable from outside
# the container.
EXPOSE 8766

# Distroless has no shell, so HEALTHCHECK NONE — operators run
# `kbounce version-check` or hit the proxy's liveness path externally.
HEALTHCHECK NONE

# nonroot user (uid 65532) is the default in the :nonroot variant.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/kbounce"]
CMD ["--help"]
