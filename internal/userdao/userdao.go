package userdao

import (
	"errors"
	"fmt"

	"github.com/NH-Homelab/auth-service/internal/database"
	"github.com/NH-Homelab/auth-service/internal/models"
)

// Package error types
var (
	ErrScanUser = errors.New("failed to scan user from DB response")
)

/*
________________________________________________________

	Get User

________________________________________________________
*/

var (
	ErrUserNotFound = errors.New("user not found")
	ErrQueryUser    = errors.New("failed to query user from db")
	ErrInvalidType  = errors.New("invalid search type")
)

// Searchtype enum
type SearchType int

const (
	Credentials SearchType = iota
	Google
)

// Queries
const (
	getAllUsersQuery       = "SELECT * FROM users;"
	getGoogleUserQuery     = "SELECT u.id, u.fullname, u.created_at, g.user_id, g.google_id, g.created_at FROM users u JOIN user_google_oauth g ON u.id = g.user_id WHERE g.google_id = $1;"
	getCredentialUserQuery = "SELECT u.id, u.fullname, u.created_at, c.user_id, c.username, c.password_hash, c.created_at, c.updated_at FROM users u JOIN user_credentials c ON u.id = c.user_id WHERE c.username = $1;"
	getGroupsByUserQuery   = "SELECT g.id FROM user_groups ug JOIN groups g ON ug.group_id = g.id WHERE ug.user_id = $1;"
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
	var (
		user models.User
		err  error
	)

	switch us.Type {
	case Credentials:
		user, err = getUserByCredentials(db, us.Value)
		if err != nil {
			return models.User{}, fmt.Errorf("GetUser: %w", err)
		}
	case Google:
		user, err = getUserByGoogle(db, us.Value)
		if err != nil {
			return models.User{}, fmt.Errorf("GetUser: %w", err)
		}
	default:
		return models.User{}, fmt.Errorf("GetUser: %w", ErrInvalidType)
	}

	// Add groups to user model
	groups, err := getGroupsByUser(db, user.ID)
	if err != nil {
		return models.User{}, fmt.Errorf("GetUser: %w", err)
	}
	user.GroupIds = groups

	return user, nil
}

func getGroupsByUser(db database.DatabaseConnection, userid int) ([]int, error) {
	res, err := db.Query(getGroupsByUserQuery, userid)
	if err != nil {
		return nil, fmt.Errorf("GetGroupsByUser: %w -- %v", ErrQueryUser, err)
	}
	defer res.Close()

	var groupIds []int
	for res.Next() {
		var groupId int
		if err := res.Scan(&groupId); err != nil {
			return nil, fmt.Errorf("GetGroupsByUser: %w -- %v", ErrScanUser, err)
		}
		groupIds = append(groupIds, groupId)
	}

	return groupIds, nil
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
			&gAuth.UserId, &gAuth.GoogleId, &gAuth.CreatedAt); err != nil {
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

/*
________________________________________________________

	Create User

________________________________________________________
*/

var (
	ErrCreateUser        = errors.New("failed to create user")
	ErrCreateGoogleCreds = errors.New("failed to create google credentials")
)

// Const SQL queries
const (
	createGoogleUserQuery        = "INSERT INTO users (fullname) VALUES ($1) RETURNING id;"
	createGoogleCredentialsQuery = "INSERT INTO user_google_oauth (user_id, google_id, refresh_token) VALUES ($1, $2, $3);"

	deleteGoogleUserQuery = "DELETE FROM users WHERE id = $1;"
)

type NewGoogleUser struct {
	GoogleId     string `json:"id"`
	RefreshToken string `json:"refresh_token"`
	Name         string `json:"name"`
	Email        string `json:"email"`
}

func CreateGoogleUser(db database.DatabaseConnection, gAuth NewGoogleUser) (models.User, error) {
	// Create the user in the users table
	user := models.User{
		Name: gAuth.Name,
		GoogleAuth: &models.GoogleAuthCredentials{
			GoogleId:     gAuth.GoogleId,
			RefreshToken: gAuth.RefreshToken,
		},
	}

	// Creates entry in 'users' table
	user, err := createGoogleUser(db, user)
	if err != nil {
		return models.User{}, fmt.Errorf("CreateGoogleUser: %w -- %v", ErrCreateUser, err)
	}

	// Creates entry in 'user_google_oauth' table -- handles rollback user creation on error
	user, err = createGoogleCredentials(db, user)
	if err != nil {
		return models.User{}, fmt.Errorf("CreateGoogleUser: %w -- %v", ErrCreateGoogleCreds, err)
	}

	return user, nil
}

// Creates user entry in 'users' table
func createGoogleUser(db database.DatabaseConnection, user models.User) (models.User, error) {
	rows, err := db.Query(createGoogleUserQuery, user.Name)
	if err != nil {
		return user, fmt.Errorf("CreateGoogleUser: %w -- %v", ErrCreateUser, err)
	}

	if ok := rows.Next(); !ok {
		return user, fmt.Errorf("CreateGoogleUser: %w -- no ID returned", ErrCreateUser)
	}

	if err = rows.Scan(&user.ID); err != nil {
		return user, fmt.Errorf("CreateGoogleUser: %w -- %v", ErrCreateUser, err)
	}

	return user, nil
}

func createGoogleCredentials(db database.DatabaseConnection, user models.User) (models.User, error) {
	// Insert Google auth credentials into the database
	if _, err := db.Exec(createGoogleCredentialsQuery, user.ID, user.GoogleAuth.GoogleId, user.GoogleAuth.RefreshToken); err != nil {
		db.Exec(deleteGoogleUserQuery, user.ID) // Rollback user creation
		return models.User{}, fmt.Errorf("CreateGoogleUser: %w -- %v", ErrCreateGoogleCreds, err)
	}
	return user, nil
}
