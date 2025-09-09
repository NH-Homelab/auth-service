package models

type GoogleOauthState struct {
	// Random generate a token for CSRF protection
	CsrfToken string `json:"csrf_token"`
	// Original request URL to redirect after OAuth flow
	Host   string `json:"host"`
	Path   string `json:"path"`
	Uri    string `json:"uri"`
	Method string `json:"method"`
}
