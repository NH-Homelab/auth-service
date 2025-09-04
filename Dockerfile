FROM golang:latest-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o auth-service main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/auth-service .
EXPOSE 8080
CMD ["./auth-service"]
