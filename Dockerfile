ARG PLATFORM="linux/amd64"

# Build stage
FROM --platform=${PLATFORM} golang:1.24.2-alpine AS build
ARG VERSION="dev"

# Set the working directory
WORKDIR /build

# Install git
RUN --mount=type=cache,target=/var/cache/apk \
    apk add git

# Build the server
# go build automatically download required module dependencies to /go/pkg/mod
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=bind,target=. \
    CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION} -X main.commit=$(git rev-parse HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /bin/github-mcp-server cmd/github-mcp-server/main.go

# Final stage
FROM --platform=${PLATFORM} node:20-slim

# Set the working directory
WORKDIR /server

# Install ca-certificates for SSL verification
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the binary from the build stage
COPY --from=build /bin/github-mcp-server .

# Install supergateway
RUN npm install -g supergateway

# Command to run the server
ENTRYPOINT ["supergateway"]
CMD ["--port", "8000", "--stdio", "./github-mcp-server stdio"]