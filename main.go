package main

import "github.com/gin-gonic/gin"

type authHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

func main() {
	r := gin.Default()

	r.GET("/customer", func(c *gin.Context) {
		h := authHeader{}
		if err := c.ShouldBindHeader(&h); err != nil {
			c.JSON(401, gin.H{
				"message": "Unauthorized",
			})
			return
		}
		if h.AuthorizationHeader == "123" {
			c.JSON(200, gin.H{
				"message": "customer",
			})
			return
		}
		c.JSON(401, gin.H{
			"message": "Unauthorized",
		})
	})

	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}
