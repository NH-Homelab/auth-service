package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/joho/godotenv"

	"github.com/NH-Homelab/auth-service/internal/models"
	"github.com/NH-Homelab/auth-service/internal/pg_db"
)

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s from %s\n", r.Method, r.URL, r.RemoteAddr)
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

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		res, err := pgDB.Query("SELECT * FROM users;")
		if err != nil {
			http.Error(w, "Failed to query database", http.StatusInternalServerError)
			return
		}
		defer res.Close()

		for res.Next() {
			var user models.User
			if err := res.Scan(&user.ID, &user.Name, &user.CreatedAt); err != nil {
				http.Error(w, "Failed to scan user", http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "User: %s, Created At: %s\n", user.Name, user.CreatedAt)
		}
	})

	http.ListenAndServe(":8080", logRequest(mux))
}
