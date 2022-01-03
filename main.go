package main

import (
	"fmt"
	"jwt-go/authenticator"
	"jwt-go/delivery/middleware"
	"jwt-go/models"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
)

func main() {
	r := gin.Default()
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})
	tokenConfig := authenticator.TokenConfig{
		ApplicationName:     "ENIGMA",
		JwtSigningMethod:    jwt.SigningMethodHS256,
		JwtSignatureKey:     "P@ssw0rd",
		AccessTokenLifeTime: 60 * time.Second,
		Client:              client,
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
			err = tokenService.StoreAccessToken(userCredential.Username, token)
			if err != nil {
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
	r.GET("/user", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": c.GetString("username"),
		})
	})

	r.POST("/logout", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "successfully logged out",
		})
	})

	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}
