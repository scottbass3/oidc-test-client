FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o oidc-test-client ./cmd/

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata jq
WORKDIR /app
COPY --from=builder /build/oidc-test-client /app/oidc-test-client
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/app/oidc-test-client"]
