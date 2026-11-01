FROM golang:1.27-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /app/threatinfoservice \
    ./cmd/threatinfoservice

FROM alpine:3.22

RUN apk --no-cache add ca-certificates \
    && addgroup -S appgroup \
    && adduser -S appuser -G appgroup

WORKDIR /app
COPY --from=builder /app/threatinfoservice /app/threatinfoservice
RUN mkdir -p /app/logs \
    && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

CMD ["/app/threatinfoservice"]