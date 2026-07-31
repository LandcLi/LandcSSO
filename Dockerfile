# ---- Build stage ----
FROM golang:1.24-alpine AS builder

WORKDIR /src

# 依赖缓存
COPY go.mod go.sum ./
RUN go mod download

# 注意：当前 go.mod 依赖本地 replace（../landc-go, ../LandcUserManager），
# 发布公共版本后即可在镜像内独立构建。
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/landc-sso ./cmd/api

# ---- Runtime stage ----
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 sso

WORKDIR /app

COPY --from=builder /out/landc-sso /app/landc-sso

USER sso

EXPOSE 8080

ENTRYPOINT ["/app/landc-sso"]
