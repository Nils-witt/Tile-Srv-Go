# tileserve-go

A small Go HTTP server for managing maps and their versioned tile uploads behind JWT authentication.
Users are stored in a Postgres `users` table (bcrypt-hashed passwords). Uploaded map versions are extracted to
`<data-root>/<uuid>/<version>/` on disk and served back at `/maps/<uuid>/version/<version>/...`.

The full API is documented in [`openapi.yaml`](cmd/tileserve-go/openapi.yaml) (OpenAPI 3.0), and served at
runtime from `/openapi.yaml` — view it with any Swagger/OpenAPI tool (e.g. paste into
https://editor.swagger.io, or `npx @redocly/cli preview-docs openapi.yaml`).

A simple browser UI is served at `/ui/` — sign in there directly, it drives the same JSON API described below.
It covers maps (create/edit/delete, upload versions, view history, preview on an interactive
[MapLibre GL](https://maplibre.org/) map) and, for admins, user management and per-map permissions. MapLibre is
loaded from the jsDelivr CDN.

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

Authenticated CRUD for a `maps` table (`uuid`, `name`, `currentVersion`, `visibleToAll`, `anonymousAllowed`,
`createdAt`, `updatedAt`, `createdBy`, `updatedBy`). `createdBy`/`updatedBy` are set from the JWT subject.

```sh
# create (private by default; add "visibleToAll":true to make it visible to every authenticated user)
curl -X POST localhost:8085/maps -H "Authorization: Bearer <token>" -d '{"name":"world","currentVersion":"1"}'

# list (only maps the acting user can see — see "Map visibility" below)
curl localhost:8085/maps -H "Authorization: Bearer <token>"

# get one
curl localhost:8085/maps/<uuid> -H "Authorization: Bearer <token>"

# update (replaces name/currentVersion/visibleToAll)
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

# compute the real-world bounds of a version's tile pyramid (used by the UI to center/zoom the preview map)
curl localhost:8085/maps/<uuid>/version/<version>/bounds -H "Authorization: Bearer <token>"
```

`GET /maps/<uuid>/version/<version>/...` serves files straight out of `<data-root>/<uuid>/<version>/` (no `can_*`
action permission required — same as the other read endpoints). It's also the one endpoint that can be called with
**no bearer token at all** if the map has `anonymousAllowed: true` — see "Anonymous tile access" below; otherwise
the acting user must still be able to *see* the map, same as everything else (see "Map visibility"). `.../bounds` is
computed on the fly by scanning that directory's `z/x/y.png` layout (no bounds are stored): it returns the lon/lat
bounding box of the tiles at the lowest zoom level present, along with that level as `minZoom` and the highest level
present as `maxZoom`; unlike raw tile files, `.../bounds` always requires authentication and view access.

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

After extraction, the server writes an `index.json` alongside the tiles listing every `{z, x, y}` tile found (sorted
by z, then x, then y), e.g. `{"tiles":[{"z":1,"x":0,"y":0},{"z":3,"x":1,"y":2}]}`. It's served like any other file at
`GET /maps/{id}/version/{version}/index.json`, letting a client enumerate a version's tiles without probing
coordinates blindly. On startup, the server also walks `-data-root` and backfills a missing `index.json` for any
existing map/version directory that doesn't already have one (e.g. one extracted by an older build), so this never
requires a re-upload.

Every user has four global permission flags — `can_create`, `can_edit`, `can_delete`, and `is_admin` — checked on
the corresponding requests (`is_admin` also gates the Users API below). Seeded/new users default to all four
`true`.

#### Map visibility

Maps are **private by default** (`visibleToAll: false`). A map is visible to a user if any of the following is
true: it's marked `visibleToAll`, the user created it, the user is an admin, the user's global `can_edit` or
`can_delete` permission already lets them act on every map (so hiding one from view would be inconsistent), or the
user holds a per-map `can_view`/`can_edit`/`can_delete` grant (see below). `GET /maps` only returns maps the acting
user can see; `GET /maps/<uuid>`, `.../versions`, `.../version/<version>/...`, and `.../version/<version>/bounds`
all return `403 Forbidden` for a map the acting user can't see.

#### Anonymous tile access

Independent of visibility, a map can opt in to letting `GET /maps/<uuid>/version/<version>/...` (raw tile files
only — nothing else) be fetched with **no bearer token whatsoever**, via `anonymousAllowed: true`. This is for
embedding a map's tiles directly in a public page/app without requiring viewers to hold a token. It's off by
default and unrelated to `visibleToAll`: a map can be private (`visibleToAll: false`, invisible in `GET /maps` and
its own `GET` to anyone without permission) while still serving tiles anonymously, or public in the UI while still
requiring a token for its tiles.

```sh
# make a map's tiles fetchable anonymously
curl -X PUT localhost:8085/maps/<uuid> -H "Authorization: Bearer <token>" \
  -d '{"name":"world","currentVersion":"2","anonymousAllowed":true}'

# now works with no Authorization header at all
curl localhost:8085/maps/<uuid>/version/<version>/0/0/0.png
```

#### Per-map permissions

On top of the global flags, admins can grant a specific user `can_view`/`can_edit`/`can_delete` on a single map,
without giving them the matching global permission (which would apply to every map). A per-map grant only ever
adds capability — a user who already has the global flag doesn't need one, and a grant can't take capability away
from someone who does. `PUT`/`DELETE /maps/<uuid>` and `POST /maps/<uuid>/upload` all accept either the global flag
or a matching per-map grant; an edit or delete grant also implies view access.

```sh
# list a map's per-user grants
curl localhost:8085/maps/<uuid>/permissions -H "Authorization: Bearer <token>"

# grant (or replace) alice's view+edit access to just this map
curl -X PUT localhost:8085/maps/<uuid>/permissions/alice -H "Authorization: Bearer <token>" \
  -d '{"canView":true,"canEdit":true,"canDelete":false}'

# revoke it
curl -X DELETE localhost:8085/maps/<uuid>/permissions/alice -H "Authorization: Bearer <token>"
```

Managing per-map permissions requires `is_admin`, same as the Users API.

#### GeoObjects API

Authenticated CRUD for a `geo_objects` table (`uuid`, `name`, `externalId`, `latitude`, `longitude`, `street`,
`housenumber`, `postcode`, `createdAt`, `updatedAt`, `createdBy`, `updatedBy`). Every geo object is tied to one
specific map version (`mapUuid` + `version`, immutable after creation) — e.g. addresses or points of interest
belonging to a particular tile-pyramid upload. Requires view access to the map to read, `can_edit` (global or
per-map) to create/update, and `can_delete` (global or per-map) to delete.

```sh
# create a geo object for a given map version
curl -X POST localhost:8085/maps/<uuid>/version/<version>/geo-objects -H "Authorization: Bearer <token>" \
  -d '{"name":"Town Hall","externalId":"ext-1","latitude":52.5,"longitude":13.4,"street":"Main St","housenumber":"1","postcode":"12345"}'

# list a version's geo objects
curl localhost:8085/maps/<uuid>/version/<version>/geo-objects -H "Authorization: Bearer <token>"

# get one
curl localhost:8085/maps/<uuid>/version/<version>/geo-objects/<geoObjectUuid> -H "Authorization: Bearer <token>"

# update (replaces name/externalId/latitude/longitude/street/housenumber/postcode)
curl -X PUT localhost:8085/maps/<uuid>/version/<version>/geo-objects/<geoObjectUuid> -H "Authorization: Bearer <token>" \
  -d '{"name":"Town Hall","latitude":52.5,"longitude":13.4}'

# delete
curl -X DELETE localhost:8085/maps/<uuid>/version/<version>/geo-objects/<geoObjectUuid> -H "Authorization: Bearer <token>"
```

### Users API

Admin-only (`is_admin`) CRUD for managing accounts. Response objects never include the password hash.

```sh
# list users
curl localhost:8085/users -H "Authorization: Bearer <token>"

# create a user
curl -X POST localhost:8085/users -H "Authorization: Bearer <token>" \
  -d '{"username":"alice","password":"changeme","canCreate":true,"canEdit":true,"canDelete":false,"isAdmin":false}'

# update permissions (and optionally password — omit/empty to leave it unchanged)
curl -X PUT localhost:8085/users/alice -H "Authorization: Bearer <token>" \
  -d '{"canCreate":true,"canEdit":true,"canDelete":true,"isAdmin":false,"password":"newpassword"}'

# delete a user (you cannot delete your own account this way)
curl -X DELETE localhost:8085/users/alice -H "Authorization: Bearer <token>"
```

`PUT` always replaces all four permission flags (they're not optional/partial); `password` is the one optional
field, left unchanged when omitted or empty.

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
