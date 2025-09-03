package jwt

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = fmt.Errorf("token is invalid")
	ErrSignToken    = fmt.Errorf("failed to sign token")
	ErrParseToken   = fmt.Errorf("failed to parse token")
)

func SignKey(claims map[string]interface{}) (string, error) {
	// Set 'exp' to 24 hours from now if not provided
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(24 * time.Hour).Unix()
	}
	// Always set 'iat' to current time
	claims["iat"] = time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))

	signedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", fmt.Errorf("SignKey: %w -- %w", ErrSignToken, err)
	}

	return signedToken, nil
}

func VerifyToken(tokenString string) (interface{}, error) {
	parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return nil, fmt.Errorf("VerifyToken: %w -- %w", ErrParseToken, err)
	}

	if !parsed.Valid {
		return nil, fmt.Errorf("VerifyToken: %w", ErrInvalidToken)
	}

	return parsed.Claims, nil
}
