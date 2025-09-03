package GoogleOauthHandler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/NH-Homelab/auth-service/internal/database"
	"github.com/NH-Homelab/auth-service/internal/jwt"
	"github.com/NH-Homelab/auth-service/internal/models"
	"github.com/NH-Homelab/auth-service/internal/userdao"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleOauthHandler struct {
	conf *oauth2.Config
	db   database.DatabaseConnection
}

func NewGoogleOauthHandler(db database.DatabaseConnection) *GoogleOauthHandler {
	oauthConfig := &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	return &GoogleOauthHandler{
		conf: oauthConfig,
		db:   db,
	}
}

func (ah GoogleOauthHandler) handleCallback(code string) (models.User, error) {
	if code == "" {
		return models.User{}, fmt.Errorf("no code in request")
	}

	// Exchange the code for a token
	token, err := ah.conf.Exchange(context.Background(), code)
	if err != nil {
		return models.User{}, fmt.Errorf("token exchange failed: %w", err)
	}

	// Extract the ID token (for user identity info)
	_, ok := token.Extra("id_token").(string)
	if !ok {
		return models.User{}, fmt.Errorf("no id_token found")
	}

	user_conf := userdao.NewGoogleUser{}

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return models.User{}, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&user_conf); err != nil {
		return models.User{}, fmt.Errorf("failed to decode user info: %w", err)
	}

	fmt.Printf("User Info: %+v\n", user_conf)

	user, err := userdao.GetUser(ah.db, userdao.UserSearch{
		Type:  userdao.Google,
		Value: user_conf.GoogleId,
	})

	switch err {
	case nil:
		fmt.Printf("User found: %v", user)
	case userdao.ErrUserNotFound:
		fmt.Printf("Creating new user: %v", user_conf)
		user, err = userdao.CreateGoogleUser(ah.db, user_conf)
		if err != nil {
			fmt.Printf("Error creating user: %v", err)
			return models.User{}, fmt.Errorf("failed to create user: %w", err)
		}
	default:
		fmt.Printf("Error retrieving user: %v", err)
		return models.User{}, fmt.Errorf("failed to retrieve user: %w", err)
	}

	// Optionally: verify the ID token
	// In production, you should parse and verify signature here.

	return user, nil
}

func (ah GoogleOauthHandler) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/google/login", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		type loginResponse struct {
			Status  string `json:"status"`
			Message string `json:"message,omitempty"`
			Token   string `json:"token,omitempty"`
		}
		if err != nil {
			url := ah.conf.AuthCodeURL("random-state-string", oauth2.AccessTypeOffline)
			http.Redirect(w, r, url, http.StatusFound)
			return
		}

		_, err = jwt.VerifyToken(cookie.Value)
		if err != nil {
			resp := loginResponse{
				Status:  "error",
				Message: "Failed to verify token",
			}
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(resp)

			// Expire cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "auth_token",
				Value:    "",
				Path:     "/",
				Domain:   os.Getenv("JWT_DOMAIN"),
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteNoneMode,
			})
			return
		}

		// User is already authenticated
		resp := loginResponse{
			Status: "success",
			Token:  cookie.Value,
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/google/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		user, err := ah.handleCallback(code)
		type callbackResponse struct {
			Status  string       `json:"status"`
			Message string       `json:"message,omitempty"`
			User    *models.User `json:"user,omitempty"`
			Token   string       `json:"token,omitempty"`
		}
		if err != nil {
			fmt.Printf("Error handling callback: %v\n", err)
			resp := callbackResponse{
				Status:  "error",
				Message: err.Error(),
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		userMap := make(map[string]interface{})
		userBytes, err := json.Marshal(user)
		if err != nil {
			fmt.Printf("Error marshalling user: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(callbackResponse{
				Status:  "error",
				Message: "Failed to marshal user",
			})
			return
		}
		if err := json.Unmarshal(userBytes, &userMap); err != nil {
			fmt.Printf("Error unmarshalling user: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(callbackResponse{
				Status:  "error",
				Message: "Failed to unmarshal user",
			})
			return
		}

		// Create cookie
		token, err := jwt.SignKey(userMap)
		if err != nil {
			resp := callbackResponse{
				Status:  "error",
				Message: "Failed to create token",
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token,
			Path:     "/",
			Domain:   os.Getenv("JWT_DOMAIN"),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
		})

		resp := callbackResponse{
			Status: "success",
			User:   &user,
			Token:  token,
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
		// Redirect to original request (if needed)
	})
}
