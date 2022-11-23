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

	api := r.Group("/api")
	api.GET("/ping", ping)
	api.GET("/test", encryptTest)
	api.POST("encrypt", encryptPayload)

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

func encryptTest(c *gin.Context) {
	response := jwt.EncryptData("hola")
	c.String(200, response)
}

func ping(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "pong",
	})
}
