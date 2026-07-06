# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/tileserve-go ./cmd/tileserve-go

FROM gcr.io/distroless/static-debian12:nonroot
ENV DATA_ROOT=/data
VOLUME ["/data"]
COPY --from=builder /out/tileserve-go /tileserve-go
EXPOSE 8085
ENTRYPOINT ["/tileserve-go"]
