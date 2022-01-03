package middleware

import (
	"fmt"
	"jwt-go/authenticator"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

type AuthTokenMiddleware struct {
	acctToken authenticator.Token
}

func NewTokenValidator(acctToken authenticator.Token) *AuthTokenMiddleware {
	return &AuthTokenMiddleware{
		acctToken: acctToken,
	}
}

func (a *AuthTokenMiddleware) RequireToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/login" {
			c.Next()
		} else {
			h := AuthHeader{}
			if err := c.ShouldBindHeader(&h); err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
				return
			}
			tokenString := strings.Replace(h.AuthorizationHeader, "Bearer ", "", -1)
			if tokenString == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
				return
			}
			token, err := a.acctToken.VerifyAccessToken(tokenString)
			if err != nil {
				fmt.Println(err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"message": "internal server error",
				})
				return
			}
			if token == nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
				return
			}
			if c.Request.URL.Path == "/logout" {
				err := a.acctToken.DeleteAccessToken(token)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"message": "error logging out",
					})
					return
				}
			} else {
				userName, err := a.acctToken.FetchAccessToken(token)
				if userName == "" || err != nil {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"message": "Unauthorized",
					})
					return
				}
				c.Set("username", userName)
			}
			c.Next()
		}
	}
}
