package models

import "github.com/golang-jwt/jwt"

type MyClaims struct {
	jwt.StandardClaims
	Username string
	Email    string
}
