# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder
LABEL org.opencontainers.image.source="https://github.com/Nils-witt/Tileserve-GO"
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/tileserve-go ./cmd/tileserve-go

FROM gcr.io/distroless/static-debian12:nonroot
ENV DATA_ROOT=/data
ENV PORT=80
VOLUME ["/data"]
COPY --from=builder /out/tileserve-go /tileserve-go
EXPOSE 80
ENTRYPOINT ["/tileserve-go"]
