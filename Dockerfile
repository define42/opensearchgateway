# ---------- build stage ----------
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Enable static binary
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Copy module files first (better caching)
COPY go.mod go.sum  ./
RUN go mod download


# Copy source
COPY *.go ./
COPY templates ./templates

# Build
RUN go build -o registry-proxy


# ---------- runtime stage ----------
FROM scratch

WORKDIR /app

# Copy binary
COPY --from=builder /app/registry-proxy /app/registry-proxy

# TLS certs will be mounted
EXPOSE 8080


ENTRYPOINT ["/app/registry-proxy"]
