package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))

type RoleType string

const (
	RoleUser  RoleType = "USER"
	RoleAdmin RoleType = "ADMIN"
)

type CustomClaims struct {
	UserID string     `json:"user_id"`
	Type   string     `json:"type"` // "access" or "refresh"
	Role   []RoleType `json:"role"`
	jwt.RegisteredClaims
}

func GenerateJWT(userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 1).Unix(),
		"type":    "access",
		"role":    []RoleType{RoleAdmin}, // TODO: Set role based on the user's access to app
	})
	return token.SignedString(jwtKey)
}

func GenerateRefreshToken(userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24 * 30).Unix(),
		"type":    "refresh",
		"role":    RoleAdmin, // TODO: Set role based on the user's access to app
	})
	return token.SignedString(jwtKey)
}

func ValidateRefreshToken(tokenString string) (string, error) {
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid or expired token")
	}

	if claims.Type != "refresh" {
		return "", fmt.Errorf("invalid token type")
	}
	return claims.UserID, nil
}
