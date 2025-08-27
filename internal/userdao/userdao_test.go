package userdao

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/NH-Homelab/auth-service/internal/database"
)

func TestGetUsers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "name", "created_at"}).
		AddRow(1, "Alice", time.Now()).
		AddRow(2, "Bob", time.Now())
	mock.ExpectQuery("SELECT \\* FROM users;").WillReturnRows(rows)

	mdb := &database.MockDB{
		QueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
			return db.Query(query, args...)
		},
	}

	users, err := GetUsers(mdb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
	if users[0].Name != "Alice" || users[1].Name != "Bob" {
		t.Errorf("unexpected user names: %+v", users)
	}
}

func TestGetUserByCredentials(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "name", "created_at", "user_id", "username", "password_hash", "created_at", "updated_at"}).
		AddRow(1, "Alice", now, 1, "alice", "hash", now, now)
	mock.ExpectQuery("SELECT u.id, u.name, u.created_at, c.user_id, c.username, c.password_hash, c.created_at, c.updated_at FROM users u JOIN user_credentials c ON u.id = c.user_id WHERE c.username = \\$1;").WillReturnRows(rows)

	mdb := &database.MockDB{
		QueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
			return db.Query(query, args...)
		},
	}

	us := UserSearch{Type: Credentials, Value: "alice"}
	user, err := GetUser(mdb, us)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Name != "Alice" || user.Credentials == nil || user.Credentials.Username != "alice" {
		t.Errorf("unexpected user: %+v", user)
	}
}

func TestGetUserByGoogle_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "name", "created_at", "user_id", "google_id", "refresh_token", "created_at"})
	mock.ExpectQuery("SELECT u.id, u.name, u.created_at, g.user_id, g.google_id, g.refresh_token, g.created_at FROM users u JOIN user_google_oauth g ON u.id = g.user_id WHERE g.google_id = \\$1;").WillReturnRows(rows)

	mdb := &database.MockDB{
		QueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
			return db.Query(query, args...)
		},
	}

	us := UserSearch{Type: Google, Value: "notfound"}
	_, err = GetUser(mdb, us)
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestGetUserByCredentials_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "name", "created_at", "user_id", "username", "password_hash", "created_at", "updated_at"})
	mock.ExpectQuery("SELECT u.id, u.name, u.created_at, c.user_id, c.username, c.password_hash, c.created_at, c.updated_at FROM users u JOIN user_credentials c ON u.id = c.user_id WHERE c.username = \\$1;").WillReturnRows(rows)

	mdb := &database.MockDB{
		QueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
			return db.Query(query, args...)
		},
	}

	us := UserSearch{Type: Credentials, Value: "notfound"}
	_, err = GetUser(mdb, us)
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestGetUserByGoogle_Found(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "name", "created_at", "user_id", "google_id", "refresh_token", "created_at"}).
		AddRow(2, "Bob", now, 2, "bob_google", "refresh_token", now)
	mock.ExpectQuery("SELECT u.id, u.name, u.created_at, g.user_id, g.google_id, g.refresh_token, g.created_at FROM users u JOIN user_google_oauth g ON u.id = g.user_id WHERE g.google_id = \\$1;").WillReturnRows(rows)

	mdb := &database.MockDB{
		QueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
			return db.Query(query, args...)
		},
	}

	us := UserSearch{Type: Google, Value: "bob_google"}
	user, err := GetUser(mdb, us)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Name != "Bob" || user.GoogleAuth == nil || user.GoogleAuth.GoogleId != "bob_google" {
		t.Errorf("unexpected user: %+v", user)
	}
}
