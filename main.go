package main

import (
	"io/ioutil"
	"net/http"

	"github.com/armzerpa/heroku-test-az/jwt"
	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	authorized := r.Group("/api", gin.BasicAuth(gin.Accounts{
		"user1": "testdigibee",
		"user2": "testaz",
	}))

	//api := r.Group("/api")
	authorized.GET("/ping", ping)
	authorized.GET("/test", encryptString)
	authorized.POST("encrypt", encryptPayload)

	r.Use(static.Serve("/", static.LocalFile("./views", true)))
	r.Run()
}

func encryptPayload(c *gin.Context) {
	jsonData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, "Invalid body")
		return
	}

	response := jwt.EncryptRawData(jsonData)
	c.String(http.StatusOK, response)
}

func encryptString(c *gin.Context) {
	key := c.Query("key")
	response := jwt.EncryptStringData(key)
	c.String(200, response)
}

func ping(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "pong",
	})
}
