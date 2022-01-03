package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"net/http"
	"strings"
	"time"
)

var ApplicationName = "JOSEP"
var JwtSigningMethod = jwt.SigningMethodHS256
var JwtSignatureKey = []byte("P@ssw0rd")

type MyClaims struct {
	jwt.StandardClaims
	Username string
	Email    string
}

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
			return
		}
		if userCredential.Username == "dodi" && userCredential.Password == "123" {
			token, err := GenerateToken(userCredential.Username, "dodi@doders.com")
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
				return
			}
			tokenString := strings.Replace(h.AuthorizationHeader, "Bearer ", "", -1)
			if tokenString == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
				return
			}
			token, err := ParseToken(tokenString)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"message": "internal server error",
				})
				return
			}
			fmt.Println(token)
			if token["iss"] == ApplicationName {
				c.Next()
				return
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
			}

		}

	}
}

func GenerateToken(username string, email string) (string, error) {
	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:   ApplicationName,
			IssuedAt: time.Now().Unix(),
		},
		Username: username,
		Email:    email,
	}
	token := jwt.NewWithClaims(JwtSigningMethod, claims)
	return token.SignedString(JwtSignatureKey)
}

func ParseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Signing method Invalid")
		} else if method != JwtSigningMethod {
			return nil, fmt.Errorf("Signing method Invalid")
		}
		return JwtSignatureKey, nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}
	return claims, nil
}
