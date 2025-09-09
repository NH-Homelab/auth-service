package authhandler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/NH-Homelab/auth-service/internal/applicationdao"
	"github.com/NH-Homelab/auth-service/internal/database"
	"github.com/NH-Homelab/auth-service/internal/jwt"
	"github.com/NH-Homelab/auth-service/internal/models"
)

type AuthHandler struct {
	db database.DatabaseConnection
}

type authResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func NewAuthHandler(db database.DatabaseConnection) *AuthHandler {
	return &AuthHandler{
		db: db,
	}
}

func (ah *AuthHandler) verifyToken(token string) (models.User, error) {
	claims, err := jwt.VerifyToken(token)
	if err != nil {
		return models.User{}, err
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return models.User{}, err
	}

	var user models.User
	if err := json.Unmarshal(claimsBytes, &user); err != nil {
		return models.User{}, err
	}

	return user, nil
}

func (ah *AuthHandler) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/auth-request", func(w http.ResponseWriter, r *http.Request) {
		// Check if they have a cookie
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			fmt.Printf("No cookie found: %v\n", err)
			resp := authResponse{
				Status:  "error",
				Message: "Cookie not found",
			}
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		user, err := ah.verifyToken(cookie.Value)
		if err != nil {
			fmt.Printf("Error verifying token: %v\n", err)
			resp := authResponse{
				Status:  "error",
				Message: "Failed to verify token",
			}
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		fmt.Printf("User: %+v\n", user)

		jwtDomain := os.Getenv("JWT_DOMAIN")
		subdomain := r.Host
		if jwtDomain != "" && len(subdomain) > len(jwtDomain) && subdomain[len(subdomain)-len(jwtDomain):] == jwtDomain {
			subdomain = subdomain[:len(subdomain)-len(jwtDomain)]
			// Remove trailing dot if present
			if len(subdomain) > 0 && subdomain[len(subdomain)-1] == '.' {
				subdomain = subdomain[:len(subdomain)-1]
			}
		}

		fmt.Printf("Subdomain: %s\n", subdomain)

		// Fetch application permissions from db
		app, err := applicationdao.GetApplicationBySubdomain(ah.db, subdomain)
		if err != nil {
			fmt.Printf("Error fetching application: %v\n", err)
			resp := authResponse{
				Status:  "error",
				Message: "Failed to fetch application information",
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		fmt.Printf("Application: %+v\n", app)

		// Check if user has permission to access the application
		if !ah.hasPermission(user, app) {
			fmt.Printf("User does not have permission to access this application: %v\n", user)
			resp := authResponse{
				Status:  "error",
				Message: "User does not have permission to access this application",
			}
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// Token is valid, proceed with the request
		resp := authResponse{
			Status:  "success",
			Message: "Authenticated request successful!",
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

func (ah *AuthHandler) hasPermission(user models.User, app models.Application) bool {
	// Check if the user has permission to access the application
	for _, groupID := range user.GroupIds {
		for _, appGroupID := range app.Groups {
			if groupID == appGroupID {
				return true
			}
		}
	}
	return false
}
