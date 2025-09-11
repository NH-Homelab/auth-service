package authhandler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/NH-Homelab/auth-service/internal/applicationdao"
	"github.com/NH-Homelab/auth-service/internal/database"
	httpresponsehandler "github.com/NH-Homelab/auth-service/internal/httpResponseHandler"
	"github.com/NH-Homelab/auth-service/internal/jwt"
	"github.com/NH-Homelab/auth-service/internal/models"
)

type AuthHandler struct {
	db database.DatabaseConnection
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
			httpresponsehandler.WriteResponse(w, r, httpresponsehandler.ResponseConfig{
				StatusCode:    http.StatusUnauthorized,
				StatusMessage: httpresponsehandler.Error,
				Message:       "No auth token provided",
			})
			return
		}

		user, err := ah.verifyToken(cookie.Value)
		if err != nil {
			httpresponsehandler.WriteResponse(w, r, httpresponsehandler.ResponseConfig{
				StatusCode:    http.StatusUnauthorized,
				StatusMessage: httpresponsehandler.Error,
				Message:       "Invalid auth token",
			})
			return
		}

		jwtDomain := os.Getenv("JWT_DOMAIN")
		subdomain := r.Host
		if jwtDomain != "" && len(subdomain) > len(jwtDomain) && subdomain[len(subdomain)-len(jwtDomain):] == jwtDomain {
			subdomain = subdomain[:len(subdomain)-len(jwtDomain)]
			// Remove trailing dot if present
			if len(subdomain) > 0 && subdomain[len(subdomain)-1] == '.' {
				subdomain = subdomain[:len(subdomain)-1]
			}
		}

		// Fetch application permissions from db
		app, err := applicationdao.GetApplicationBySubdomain(ah.db, subdomain)
		if err != nil {
			httpresponsehandler.WriteResponse(w, r, httpresponsehandler.ResponseConfig{
				StatusCode:    http.StatusInternalServerError,
				StatusMessage: httpresponsehandler.Error,
				Message:       "Failed to fetch application from database",
			})
			return
		}

		// Check if user has permission to access the application
		if !ah.hasPermission(user, app) {
			httpresponsehandler.WriteResponse(w, r, httpresponsehandler.ResponseConfig{
				StatusCode:    http.StatusForbidden,
				StatusMessage: httpresponsehandler.Error,
				Message:       fmt.Sprintf("User %s does not have permission to access application %s", user.Name, app.Name),
			})
			return
		}

		// Token is valid, proceed with the request
		httpresponsehandler.WriteResponse(w, r, httpresponsehandler.ResponseConfig{
			StatusCode:    http.StatusOK,
			StatusMessage: httpresponsehandler.Success,
			Message:       "User is authorized",
		})
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
