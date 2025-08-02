# Build the binary
FROM golang:alpine AS builder
RUN apk add --no-cache make build-base
WORKDIR /app
COPY . .
RUN go mod download
RUN make build

# Run the binary
FROM alpine:latest

COPY --from=builder /app/Auth /app/

RUN ls app

EXPOSE 8080
ENTRYPOINT ["/app/Auth"]
