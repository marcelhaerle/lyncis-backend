# Stage 1: Build the Go binary
FROM golang:1.22-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Install git and ca-certificates (needed for fetching dependencies and HTTPS calls to DB/external services)
RUN apk add --no-cache git ca-certificates tzdata update-ca-certificates

# Copy go.mod and go.sum to leverage Docker cache for dependencies
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the statically linked Go binary
# CGO_ENABLED=0 ensures no C libraries are required in the runtime image
# -ldflags="-w -s" reduces binary size by removing DWARF debugging information and symbol table
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o lyncis-backend ./cmd/server

# Stage 2: Create the minimal runtime image
FROM alpine:3.19

# Create a non-root user and group for security
RUN addgroup -S lyncis && adduser -S lyncis -G lyncis

# Import necessary ca-certificates from the builder stage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Set the working directory in the minimal image
WORKDIR /app

# Copy the statically compiled binary from the builder stage
COPY --from=builder /app/lyncis-backend .

# Change ownership of the app directory to the non-root user
RUN chown -R lyncis:lyncis /app

# Switch to the non-root user
USER lyncis

# Expose the default port the application runs on
EXPOSE 3000

# Command to run the executable
CMD ["./lyncis-backend"]
