package httpresponsehandler

import (
	"encoding/json"
	"log"
	"net/http"
)

type Status string

const (
	Success Status = "success"
	Error   Status = "error"
)

func (s Status) String() string {
	return string(s)
}

func (s Status) IsSuccess() bool {
	return s == Success
}

func (s Status) IsError() bool {
	return s == Error
}

// Status message enum
type StatusMessage string

type ResponseConfig struct {
	StatusCode    int
	StatusMessage Status
	Message       string
	Err           error
}

func WriteResponse(w http.ResponseWriter, r *http.Request, config ResponseConfig) {
	method := r.Header.Get("X-Original-Method")
	host := r.Header.Get("X-Original-Host")
	url := r.Header.Get("X-Original-URL")

	if config.Err != nil {
		log.Printf("Request %s %s%s -- Error: %v\n", method, host, url, config.Err)
	}

	log.Printf("Request %s %s%s -- Writing response: %d %s - %s\n", method, host, url, config.StatusCode, config.StatusMessage, config.Message)

	w.WriteHeader(config.StatusCode)
	response := map[string]interface{}{
		"status":  config.StatusMessage.String(),
		"message": config.Message,
	}
	_ = json.NewEncoder(w).Encode(response)
}
