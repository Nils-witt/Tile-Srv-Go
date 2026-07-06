package main

import (
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
	authUsername := flag.String("auth-username", envOrDefault("AUTH_USERNAME", "demouser"), "username accepted by /login (env AUTH_USERNAME)")
	authPassword := flag.String("auth-password", envOrDefault("AUTH_PASSWORD", "demouser"), "password accepted by /login (env AUTH_PASSWORD)")
	port := flag.String("port", envOrDefault("PORT", "8085"), "port to listen on (env PORT)")
	flag.Parse()

	if *jwtSecret == "" || *authUsername == "" || *authPassword == "" {
		log.Fatal("jwt-secret, auth-username, and auth-password are all required")
	}
	secret := []byte(*jwtSecret)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/login", loginHandler(secret, *authUsername, *authPassword))
	mux.Handle("/", requireAuth(secret, http.FileServer(http.Dir(*dataRoot))))

	addr := ":" + *port
	log.Printf("tileserve-go listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
