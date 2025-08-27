package database

import (
	"database/sql"
)

type MockDB struct {
	ExecFunc  func(string, ...interface{}) (sql.Result, error)
	QueryFunc func(string, ...interface{}) (*sql.Rows, error)
}

func (m *MockDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	if m.ExecFunc != nil {
		return m.ExecFunc(query, args...)
	}
	return nil, nil
}

func (m *MockDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	if m.QueryFunc != nil {
		return m.QueryFunc(query, args...)
	}
	return nil, nil
}
