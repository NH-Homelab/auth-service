package models

import "time"

type User struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	GroupIds  []int     `json:"groups,omitempty"`

	Credentials *Credentials           `json:"credentials,omitempty"`
	GoogleAuth  *GoogleAuthCredentials `json:"googleauth,omitempty"`
}

type Credentials struct {
	UserId       int       `json:"user_id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type GoogleAuthCredentials struct {
	UserId       int       `json:"user_id"`
	GoogleId     string    `json:"google_id"`
	RefreshToken string    `json:"refresh_token"`
	CreatedAt    time.Time `json:"created_at"`
}
