package userdao

import (
	"errors"
	"fmt"

	"github.com/NH-Homelab/auth-service/internal/database"
	"github.com/NH-Homelab/auth-service/internal/models"
)

type SearchType int

// SearchType enums
const (
	Credentials SearchType = iota
	Google
)

// Const SQL queries
const (
	getAllUsersQuery       = "SELECT * FROM users;"
	getGoogleUserQuery     = "SELECT u.id, u.name, u.created_at, g.user_id, g.google_id, g.refresh_token, g.created_at FROM users u JOIN user_google_oauth g ON u.id = g.user_id WHERE g.google_id = $1;"
	getCredentialUserQuery = "SELECT u.id, u.name, u.created_at, c.user_id, c.username, c.password_hash, c.created_at, c.updated_at FROM users u JOIN user_credentials c ON u.id = c.user_id WHERE c.username = $1;"
)

// Error Types
var (
	ErrUserNotFound = errors.New("user not found")
	ErrScanUser     = errors.New("failed to scan user from DB response")
	ErrQueryUser    = errors.New("failed to query user from db")
	ErrInvalidType  = errors.New("invalid search type")
)

type UserSearch struct {
	Type  SearchType
	Value string
}

// GetUsers fetches all users from the database without loading any authentication credentials.
func GetUsers(db database.DatabaseConnection) ([]models.User, error) {
	res, err := db.Query(getAllUsersQuery)
	if err != nil {
		return nil, fmt.Errorf("GetUsers: %w -- %v", ErrQueryUser, err)
	}
	defer res.Close()

	var users []models.User

	for res.Next() {
		var user models.User
		if err := res.Scan(&user.ID, &user.Name, &user.CreatedAt); err != nil {
			return nil, fmt.Errorf("GetUsers: %w -- %v", ErrScanUser, err)
		}
		users = append(users, user)
	}

	return users, nil
}

func GetUser(db database.DatabaseConnection, us UserSearch) (models.User, error) {
	switch us.Type {
	case Credentials:
		return getUserByCredentials(db, us.Value)
	case Google:
		return getUserByGoogle(db, us.Value)
	default:
		return models.User{}, fmt.Errorf("GetUser: %w", ErrInvalidType)
	}
}

func getUserByGoogle(db database.DatabaseConnection, googleId string) (models.User, error) {
	res, err := db.Query(getGoogleUserQuery, googleId)
	if err != nil {
		return models.User{}, fmt.Errorf("GetUser - Google Id: %w -- %v", ErrQueryUser, err)
	}
	defer res.Close()

	if res.Next() {
		var user models.User
		var gAuth models.GoogleAuthCredentials
		if err := res.Scan(&user.ID, &user.Name, &user.CreatedAt,
			&gAuth.UserId, &gAuth.GoogleId, &gAuth.RefreshToken, &gAuth.CreatedAt); err != nil {
			return models.User{}, fmt.Errorf("GetUser - Google Id: %w -- %v", ErrScanUser, err)
		}
		user.GoogleAuth = &gAuth
		return user, nil
	}

	return models.User{}, ErrUserNotFound
}

func getUserByCredentials(db database.DatabaseConnection, username string) (models.User, error) {
	res, err := db.Query(getCredentialUserQuery, username)
	if err != nil {
		return models.User{}, fmt.Errorf("GetUser - Credentials: %w -- %v", ErrQueryUser, err)
	}
	defer res.Close()

	if res.Next() {
		var user models.User
		var creds models.Credentials
		if err := res.Scan(&user.ID, &user.Name, &user.CreatedAt,
			&creds.UserId, &creds.Username, &creds.PasswordHash, &creds.CreatedAt, &creds.UpdatedAt); err != nil {
			return models.User{}, fmt.Errorf("GetUser - Credentials: %w -- %v", ErrScanUser, err)
		}
		user.Credentials = &creds
		return user, nil
	}

	return models.User{}, ErrUserNotFound
}
