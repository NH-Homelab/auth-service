package models

import "time"

type User struct {
	ID        int
	Name      string
	CreatedAt time.Time

	Credentials *Credentials

	GoogleAuth *GoogleAuthCredentials
}

type Credentials struct {
	UserId       int
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type GoogleAuthCredentials struct {
	UserId       int
	GoogleId     string
	RefreshToken string
	CreatedAt    time.Time
}
