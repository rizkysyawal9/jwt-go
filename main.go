package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type authHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

type credential struct {
	Username string
	Password string
}

func main() {
	r := gin.Default()
	r.Use(AuthTokenMiddleware())
	r.POST("/login", func(c *gin.Context) {
		userCredential := credential{}
		if err := c.ShouldBindJSON(&userCredential); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "can't bind struct",
			})
		}
		if userCredential.Username == "dodi" && userCredential.Password == "123" {
			c.JSON(http.StatusOK, gin.H{
				"token": "123",
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

func AuthTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/login" {
			c.Next()
		} else {
			h := authHeader{}
			if err := c.ShouldBindHeader(&h); err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
			}
			if h.AuthorizationHeader == "123" {
				c.Next()
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
			}
		}

	}
}
