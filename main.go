package main

import (
	"fmt"
	"jwt-go/authenticator"
	"jwt-go/delivery/middleware"
	"jwt-go/models"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func main() {
	r := gin.Default()
	tokenConfig := authenticator.TokenConfig{
		ApplicationName:     "ENIGMA",
		JwtSigningMethod:    jwt.SigningMethodHS256,
		JwtSignatureKey:     "P@ssw0rd",
		AccessTokenLifeTime: 30 * time.Second,
	}
	tokenService := authenticator.NewTokenService(tokenConfig)
	r.Use(middleware.NewTokenValidator(tokenService).RequireToken())

	r.POST("/login", func(c *gin.Context) {
		userCredential := models.Credential{}
		if err := c.ShouldBindJSON(&userCredential); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "can't bind struct",
			})
			return
		}
		if userCredential.Username == "dodi" && userCredential.Password == "123" {
			token, err := tokenService.CreateAccessToken(&userCredential)
			if err != nil {
				fmt.Println(err)
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"message": "something went wrong with jwt",
				})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"token": token,
			})
		} else {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"message": "wrong credentials",
			})
		}
	})

	r.GET("/customer", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "accessed",
		})
	})

	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}

// func GenerateToken(username string, email string) (string, error) {
// 	claims := models.MyClaims{
// 		StandardClaims: jwt.StandardClaims{
// 			Issuer:   ApplicationName,
// 			IssuedAt: time.Now().Unix(),
// 		},
// 		Username: username,
// 		Email:    email,
// 	}
// 	token := jwt.NewWithClaims(JwtSigningMethod, claims)
// 	return token.SignedString(JwtSignatureKey)
// }

// func ParseToken(tokenString string) (jwt.MapClaims, error) {
// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("Signing method Invalid")
// 		} else if method != JwtSigningMethod {
// 			return nil, fmt.Errorf("Signing method Invalid")
// 		}
// 		return JwtSignatureKey, nil
// 	})
// 	claims, ok := token.Claims.(jwt.MapClaims)
// 	if !ok || !token.Valid {
// 		return nil, err
// 	}
// 	return claims, nil
// }
