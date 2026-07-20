# tileserve-go

A small Go HTTP server for managing maps and their versioned tile uploads behind JWT authentication.
Users are stored in a Postgres `users` table (bcrypt-hashed passwords). Uploaded map versions are extracted to
`<data-root>/<uuid>/<version>/` on disk and served back at `/maps/<uuid>/version/<version>/...`.

The full API is documented in [`openapi.yaml`](openapi.yaml) (OpenAPI 3.0) — view it with any Swagger/OpenAPI
tool (e.g. paste into https://editor.swagger.io, or `npx @redocly/cli preview-docs openapi.yaml`).

A simple browser UI for managing maps (create/edit/delete, upload versions, view history) is served at `/ui/`.
It's a single static page — sign in there directly, it drives the same JSON API described below.

## Run

```sh
go run ./cmd/tileserve-go \
  -jwt-secret changeme \
  -db-dsn "postgres://user:pass@localhost:5432/tileserve?sslmode=disable" \
  -seed-username admin \
  -seed-password changeme \
  -data-root ./data
```

The `users` table is created automatically on startup if it doesn't exist. `-seed-username`/`-seed-password`
create that account if it isn't already present (no-op otherwise) — useful for bootstrapping the first user.

## Usage

```sh
# get a token (default TTL of 24h)
curl -X POST localhost:8085/login -d '{"username":"admin","password":"changeme"}'

# request a token with a custom TTL (in seconds, capped at 7 days)
curl -X POST localhost:8085/login -d '{"username":"admin","password":"changeme","ttl_seconds":3600}'
```

The token can be used on any endpoint below either as `Authorization: Bearer <token>` or as a `?token=<token>`
query parameter.

### Maps API

Authenticated CRUD for a `maps` table (`uuid`, `name`, `currentVersion`, `createdAt`, `updatedAt`, `createdBy`,
`updatedBy`). `createdBy`/`updatedBy` are set from the JWT subject.

```sh
# create
curl -X POST localhost:8085/maps -H "Authorization: Bearer <token>" -d '{"name":"world","currentVersion":"1"}'

# list
curl localhost:8085/maps -H "Authorization: Bearer <token>"

# get one
curl localhost:8085/maps/<uuid> -H "Authorization: Bearer <token>"

# update (replaces name/currentVersion)
curl -X PUT localhost:8085/maps/<uuid> -H "Authorization: Bearer <token>" -d '{"name":"world","currentVersion":"2"}'

# delete
curl -X DELETE localhost:8085/maps/<uuid> -H "Authorization: Bearer <token>"

# upload a new version: the request body is a zip file, extracted to
# <data-root>/<uuid>/<version>/, where <version> is one more than the highest
# version recorded in the map_versions history (0 if none yet). The response
# is the updated map, with the new current version.
curl -X POST localhost:8085/maps/<uuid>/upload -H "Authorization: Bearer <token>" --data-binary @version.zip

# list upload history for a map (most recent first)
curl localhost:8085/maps/<uuid>/versions -H "Authorization: Bearer <token>"

# fetch an extracted tile file from a given version
curl localhost:8085/maps/<uuid>/version/<version>/0/0/0.png -H "Authorization: Bearer <token>"
```

`GET /maps/<uuid>/version/<version>/...` serves files straight out of `<data-root>/<uuid>/<version>/` (any
authenticated user, no `can_*` permission required — same as the other read endpoints).

Each `/upload` writes a row (`version`, `createdAt`, `createdBy`) to a separate `map_versions` table in the same
transaction that bumps the map's `currentVersion`, giving a full history of every version ever uploaded. That
history — not the map's `currentVersion` field — is the source of truth for picking the next version number, so
manually changing `currentVersion` via `PUT` can't cause a later upload to collide with or overwrite an existing
version directory. Deleting a map cascades and removes its version history too. Uploads are capped at 1 GiB and
require the `can_create` permission (see below).

The zip's contents should form a numeric tile pyramid: every directory name must be all digits, and every file
must be named `<number>.png` (e.g. `3/1/2.png`, or `5.png` at the top level). Entries that don't match this —
non-numeric directories, non-`.png` files, non-numeric filenames, symlinks, path-traversal attempts — are silently
skipped (and logged server-side) rather than failing the whole upload; everything else in the zip still gets
extracted and the version is still created (even if it ends up empty).

Every user has three global permission flags — `can_create`, `can_edit`, `can_delete` — checked on the
corresponding write requests (list/get are unrestricted for any authenticated user). Seeded/new users default
to all three `true`. There's no management endpoint yet; toggle them directly in Postgres:

```sql
UPDATE users SET can_delete = false WHERE username = 'someuser';
```

## Config

Set via flags or matching env vars (`-data-root`/`DATA_ROOT`, `-jwt-secret`/`JWT_SECRET`, `-db-dsn`/`DATABASE_URL`,
`-seed-username`/`SEED_USERNAME`, `-seed-password`/`SEED_PASSWORD`, `-port`/`PORT`, default port `8085`).
`jwt-secret` and `db-dsn` are required.

## Docker

```sh
docker build -t tileserve-go .
docker run -p 8085:8085 \
  -e JWT_SECRET=changeme \
  -e DATABASE_URL="postgres://user:pass@db:5432/tileserve?sslmode=disable" \
  -e SEED_USERNAME=admin -e SEED_PASSWORD=changeme \
  -v /path/to/data:/data tileserve-go
```
