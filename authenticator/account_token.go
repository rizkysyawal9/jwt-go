package authenticator

import (
	"fmt"
	"jwt-go/models"
	"time"

	"github.com/golang-jwt/jwt"
)

type Token interface {
	CreateAccessToken(cred *models.Credential) (string, error)
	VerifyAccessToken(tokenString string) (jwt.MapClaims, error)
}

type token struct {
	Config TokenConfig
}

type TokenConfig struct {
	ApplicationName     string
	JwtSignatureKey     string
	JwtSigningMethod    *jwt.SigningMethodHMAC
	AccessTokenLifeTime time.Duration
}

func NewTokenService(config TokenConfig) Token {
	return &token{
		Config: config,
	}
}

func (t *token) CreateAccessToken(cred *models.Credential) (string, error) {
	now := time.Now().UTC()
	end := now.Add(t.Config.AccessTokenLifeTime)

	claims := models.MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer: t.Config.ApplicationName,
		},
		Username: cred.Username,
		Email:    cred.Email,
	}
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = end.Unix()

	token := jwt.NewWithClaims(t.Config.JwtSigningMethod, claims)
	fmt.Println(t.Config.JwtSigningMethod)
	fmt.Println(t.Config.JwtSignatureKey)
	return token.SignedString([]byte(t.Config.JwtSignatureKey))
}

func (t *token) VerifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			fmt.Println("error flag one")
			return nil, fmt.Errorf("Signing method Invalid")
		} else if method != t.Config.JwtSigningMethod {
			fmt.Println("error flag two")
			return nil, fmt.Errorf("Signing method Invalid")
		}
		return []byte(t.Config.JwtSignatureKey), nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		fmt.Println("error flag three")
		return nil, err
	}
	return claims, nil
}
