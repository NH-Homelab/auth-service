package GoogleOauthHandler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

// generateCSRFToken generates a cryptographically secure random CSRF token
func generateCSRFToken() (string, error) {
	b := make([]byte, 32) // 32 bytes = 256 bits
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// verifyOAuthState verifies and decodes the signed OAuth state
func verifyOAuthState(signedState string) (models.GoogleOauthState, error) {
	var state models.GoogleOauthState

	// Verify the signed state
	claims, err := jwt.VerifyToken(signedState)
	if err != nil {
		return state, fmt.Errorf("failed to verify state token: %w", err)
	}

	// Convert claims back to state struct
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return state, fmt.Errorf("failed to marshal claims: %w", err)
	}

	if err := json.Unmarshal(claimsBytes, &state); err != nil {
		return state, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	return state, nil
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
			// Generate a secure CSRF token
			csrfToken, err := generateCSRFToken()
			if err != nil {
				http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
				return
			}

			// Create State object with CSRF token and request info
			state := models.GoogleOauthState{
				CsrfToken: csrfToken,
				Host:      r.Header.Get("X-Original-Host"),
				Path:      r.Header.Get("X-Original-Path"),
				Uri:       r.Header.Get("X-Original-URI"),
				Method:    r.Header.Get("X-Original-Method"),
				Scheme:    r.Header.Get("X-Original-Scheme"),
			}

			// Convert state to map for JWT signing
			stateBytes, err := json.Marshal(state)
			if err != nil {
				http.Error(w, "Failed to marshal state", http.StatusInternalServerError)
				return
			}

			var stateMap map[string]interface{}
			if err := json.Unmarshal(stateBytes, &stateMap); err != nil {
				http.Error(w, "Failed to convert state to map", http.StatusInternalServerError)
				return
			}

			// Sign the state using JWT
			signedState, err := jwt.SignKey(stateMap)
			if err != nil {
				http.Error(w, "Failed to sign state", http.StatusInternalServerError)
				return
			}

			// Redirect to Google OAuth with the signed state
			url := ah.conf.AuthCodeURL(signedState, oauth2.AccessTypeOffline)
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
		type callbackResponse struct {
			Status  string       `json:"status"`
			Message string       `json:"message,omitempty"`
			User    *models.User `json:"user,omitempty"`
			Token   string       `json:"token,omitempty"`
		}

		// Verify the OAuth state parameter
		stateParam := r.URL.Query().Get("state")
		if stateParam == "" {
			resp := callbackResponse{
				Status:  "error",
				Message: "Missing state parameter",
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		original_request, err := verifyOAuthState(stateParam)
		if err != nil {
			fmt.Printf("State verification failed: %v\n", err)
			resp := callbackResponse{
				Status:  "error",
				Message: "Invalid state parameter",
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		code := r.URL.Query().Get("code")
		user, err := ah.handleCallback(code)

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

		Url := fmt.Sprintf("%s%s%s", original_request.Scheme, original_request.Host, original_request.Uri)

		fmt.Printf("Redirecting user to original URL: %s\n", Url)

		http.Redirect(w, r, Url, http.StatusFound)

		// resp := callbackResponse{
		// 	Status: "success",
		// 	User:   &user,
		// 	Token:  token,
		// }

		// w.WriteHeader(http.StatusOK)
		// _ = json.NewEncoder(w).Encode(resp)
	})
}
