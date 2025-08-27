package pg_db

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type PostgresDB struct {
	Conn *sql.DB
}

type Pg_Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Dbname   string
}

func NewPostgresDB(config Pg_Config) (*PostgresDB, error) {
	dataSourceName := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.Host, config.Port, config.User, config.Password, config.Dbname)

	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &PostgresDB{Conn: db}, nil
}

func (pg *PostgresDB) Close() error {
	return pg.Conn.Close()
}

func (pg *PostgresDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return pg.Conn.Exec(query, args...)
}

func (pg *PostgresDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return pg.Conn.Query(query, args...)
}
