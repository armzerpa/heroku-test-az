package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	router := gin.Default()
	router.GET("/ping", ping)

	router.Run("localhost:" + port)
}

func ping(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, "pong")
}
