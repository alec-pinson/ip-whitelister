FROM golang:1.17-alpine AS build_base
WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN go build -o ./out/my-app .

# Start fresh from a smaller image
FROM alpine:3.15.0
RUN apk add ca-certificates
COPY --from=build_base /build/out/my-app /app/ip-whitelister
# This container exposes port 8080 to the outside world
EXPOSE 8080
WORKDIR /app
CMD ["/app/ip-whitelister"]
