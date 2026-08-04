package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
)

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	dataRoot := flag.String("data-root", envOrDefault("DATA_ROOT", "./data"), "directory to serve files from (env DATA_ROOT)")
	jwtSecret := flag.String("jwt-secret", envOrDefault("JWT_SECRET", "secretsecret"), "secret used to sign and verify JWTs (env JWT_SECRET)")
	dbDSN := flag.String("db-dsn", envOrDefault("DATABASE_URL", "postgres://user:pass@localhost:5432/db"), "postgres connection string, e.g. postgres://user:pass@host:5432/db (env DATABASE_URL)")
	seedUsername := flag.String("seed-username", envOrDefault("SEED_USERNAME", "admin"), "username to create on startup if it doesn't already exist (env SEED_USERNAME)")
	seedPassword := flag.String("seed-password", envOrDefault("SEED_PASSWORD", "admin"), "password for -seed-username (env SEED_PASSWORD)")
	port := flag.String("port", envOrDefault("PORT", "8085"), "port to listen on (env PORT)")
	flag.Parse()

	if *jwtSecret == "" || *dbDSN == "" {
		log.Fatal("jwt-secret and db-dsn are both required")
	}
	secret := []byte(*jwtSecret)

	ctx := context.Background()
	store, err := NewStore(ctx, *dbDSN)
	if err != nil {
		log.Fatalf("connect to postgres: %v", err)
	}
	defer store.Close()

	if err := store.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	if *seedUsername != "" && *seedPassword != "" {
		if err := store.SeedUser(ctx, *seedUsername, *seedPassword); err != nil {
			log.Fatalf("seed user: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/login", loginHandler(secret, store))
	mux.HandleFunc("/ui/", uiHandler())
	mux.Handle("/maps", requireAuth(secret, mapsCollectionHandler(store)))
	// optionalAuth, not requireAuth: a map's version file serving route may
	// be reachable without a token at all if that map has anonymousAllowed
	// set — mapsItemHandler enforces auth itself on every other route.
	mux.Handle("/maps/", optionalAuth(secret, mapsItemHandler(store, *dataRoot)))
	mux.Handle("/users", requireAuth(secret, usersCollectionHandler(store)))
	mux.Handle("/users/", requireAuth(secret, userItemHandler(store)))

	addr := ":" + *port
	log.Printf("tileserve-go listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
