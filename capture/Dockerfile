# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache libpcap-dev gcc musl-dev

# Copy Go files
COPY go.mod go.sum ./
COPY capture/ ./capture/
COPY api/ ./api/
COPY response/ ./response/

# Build binary
RUN cd capture && go build -o /app/capture-binary .

# Runtime stage
FROM alpine:latest

RUN apk add --no-cache libpcap

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/capture-binary .

# Set network mode to host (required for packet capture)
ENTRYPOINT ["./capture-binary"]
