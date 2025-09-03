package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/joho/godotenv"

	"github.com/NH-Homelab/auth-service/internal/GoogleOauthHandler"
	authhandler "github.com/NH-Homelab/auth-service/internal/authHandler"
	"github.com/NH-Homelab/auth-service/internal/pg_db"
)

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s from %s\n", r.Method, r.URL, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func setContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	mux := http.NewServeMux()

	db_port, err := strconv.Atoi(os.Getenv("DB_PORT"))
	if err != nil {
		log.Fatal("Could not parse db port")
	}

	pgConfig := pg_db.Pg_Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     db_port,
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		Dbname:   os.Getenv("DB_NAME"),
	}

	pgDB, err := pg_db.NewPostgresDB(pgConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pgDB.Close()

	// TODO: create separate mux for this if I want to apply middlewares
	gah := GoogleOauthHandler.NewGoogleOauthHandler(pgDB)
	gah.RegisterHandlers(mux)

	ah := authhandler.NewAuthHandler(pgDB)
	ah.RegisterHandlers(mux)

	useTLS := os.Getenv("USE_TLS") == "true"
	if useTLS {
		certFile := os.Getenv("TLS_CERT_FILE")
		keyFile := os.Getenv("TLS_KEY_FILE")
		if certFile == "" || keyFile == "" {
			log.Fatal("TLS enabled but TLS_CERT_FILE or TLS_KEY_FILE not set")
		}
		log.Printf("Starting HTTPS server on :8443...")
		err := http.ListenAndServeTLS(":8443", certFile, keyFile, logRequest(setContentType(mux)))
		if err != nil {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	} else {
		// For production behind nginx, use plain HTTP:
		// http.ListenAndServe(":8080", logRequest(mux))
		log.Printf("Starting HTTP server on :8080...")
		err := http.ListenAndServe(":8080", logRequest(setContentType(mux)))
		if err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}
}
