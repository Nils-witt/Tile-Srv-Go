# tileserve-go

A small Go HTTP server that serves files from a data directory behind JWT authentication.

## Run

```sh
go run ./cmd/tileserve-go \
  -jwt-secret changeme \
  -auth-username admin \
  -auth-password changeme \
  -data-root ./data
```

## Usage

```sh
# get a token (default TTL of 24h)
curl -X POST localhost:8085/login -d '{"username":"admin","password":"changeme"}'

# request a token with a custom TTL (in seconds, capped at 7 days)
curl -X POST localhost:8085/login -d '{"username":"admin","password":"changeme","ttl_seconds":3600}'

# use it to fetch a file
curl -H "Authorization: Bearer <token>" localhost:8085/some-file.txt

# or pass it as a query parameter
curl "localhost:8085/some-file.txt?token=<token>"
```

## Config

Set via flags or matching env vars (`-data-root`/`DATA_ROOT`, `-jwt-secret`/`JWT_SECRET`, `-auth-username`/`AUTH_USERNAME`, `-auth-password`/`AUTH_PASSWORD`, `-port`/`PORT`, default port `8085`).

## Docker

```sh
docker build -t tileserve-go .
docker run -p 8085:8085 -e JWT_SECRET=changeme -e AUTH_USERNAME=admin -e AUTH_PASSWORD=changeme -v /path/to/data:/data tileserve-go
```
