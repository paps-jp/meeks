# Meeks server image: a single static Go binary with the web client embedded.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /meeks .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /meeks /meeks
# IP logs and join-request state live here (mount a volume; owner uid 65532).
WORKDIR /data
USER nonroot
EXPOSE 8080 3479/tcp 3479/udp
ENTRYPOINT ["/meeks", "serve"]
