package main

import (
	"encoding/json"
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
	authorized.POST("decrypt", decryptPayload)

	r.Use(static.Serve("/", static.LocalFile("./views", true)))
	r.Run()
}

func encryptPayload(c *gin.Context) {
	jsonData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, "Invalid body")
		return
	}
	responseString := jwt.EncryptRawData(jsonData)

	data := jwt.Serialize{}
	json.Unmarshal([]byte(responseString), &data)

	c.IndentedJSON(http.StatusOK, data)
}

func decryptPayload(c *gin.Context) {
	var data jwt.Serialize
	error := c.BindJSON(&data)
	if error != nil {
		c.IndentedJSON(http.StatusBadRequest, "Invalid body")
		return
	}
	responseString := jwt.DecryptRawData(data)

	c.String(http.StatusOK, responseString)
}

func encryptString(c *gin.Context) {
	key := c.Query("value")
	if key == "" {
		c.IndentedJSON(http.StatusBadRequest, "value key invalid")
		return
	}
	responseString := jwt.EncryptStringData(key)

	data := jwt.Serialize{}
	json.Unmarshal([]byte(responseString), &data)

	c.IndentedJSON(http.StatusOK, data)
}

func ping(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "pong",
	})
}
