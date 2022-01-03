package authenticator

import (
	"context"
	"errors"
	"fmt"
	"jwt-go/models"
	"time"

	. "github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type TokenDetail struct {
	AccessToken string
	AccesssUuid string
	AtExpires   int64
}

type AccessDetails struct {
	Username    string
	AccessToken string
	AccessUuid  string
	AtExpires   int64
}

type Token interface {
	CreateAccessToken(cred *models.Credential) (*TokenDetail, error)
	VerifyAccessToken(tokenString string) (*AccessDetails, error)
	StoreAccessToken(userName string, tokenDetail *TokenDetail) error
	FetchAccessToken(accessDetails *AccessDetails) (string, error)
	DeleteAccessToken(accessDetails *AccessDetails) error
}

type token struct {
	Config TokenConfig
}

type TokenConfig struct {
	ApplicationName     string
	JwtSignatureKey     string
	JwtSigningMethod    *jwt.SigningMethodHMAC
	AccessTokenLifeTime time.Duration
	Client              *Client
}

func NewTokenService(config TokenConfig) Token {
	return &token{
		Config: config,
	}
}

func (t *token) CreateAccessToken(cred *models.Credential) (*TokenDetail, error) {
	td := &TokenDetail{}
	now := time.Now().UTC()
	end := now.Add(t.Config.AccessTokenLifeTime)

	td.AtExpires = end.Unix()
	td.AccesssUuid = uuid.New().String()

	claims := models.MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer: t.Config.ApplicationName,
		},
		Username:   cred.Username,
		Email:      cred.Email,
		AccessUUID: td.AccesssUuid,
	}
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = end.Unix()

	token := jwt.NewWithClaims(t.Config.JwtSigningMethod, claims)
	newToken, err := token.SignedString([]byte(t.Config.JwtSignatureKey))
	td.AccessToken = newToken
	if err != nil {
		return nil, err
	}
	return td, nil
}

func (t *token) VerifyAccessToken(tokenString string) (*AccessDetails, error) {
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
	accessUUID := claims["AccessUUID"].(string)
	userName := claims["Username"].(string)
	return &AccessDetails{
		AccessUuid: accessUUID,
		Username:   userName,
	}, nil
}

func (t *token) StoreAccessToken(userName string, tokenDetail *TokenDetail) error {
	at := time.Unix(tokenDetail.AtExpires, 0)
	now := time.Now()
	err := t.Config.Client.Set(context.Background(), tokenDetail.AccesssUuid, userName, at.Sub(now)).Err()
	if err != nil {
		return err
	}
	return nil
}

func (t *token) FetchAccessToken(accessDetails *AccessDetails) (string, error) {
	if accessDetails != nil {
		userName, err := t.Config.Client.Get(context.Background(), accessDetails.AccessUuid).Result()
		if err != nil {
			return "", err
		}
		return userName, nil
	} else {
		return "", errors.New("invalid Access")
	}
}

func (t *token) DeleteAccessToken(accessDetails *AccessDetails) error {
	_, err := t.Config.Client.Del(context.Background(), accessDetails.AccessUuid).Result()
	if err != nil {
		return err
	}
	return nil
}
