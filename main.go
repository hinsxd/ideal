package main

import (
	"net/http"
	"ideal/api"
	"ideal/router"
	"ideal/config"
	"log"
)

func main() {
	log.Print("main.go loaded.")
	r := router.InitRouter()
	http.ListenAndServe(config.ServerAddr, api.SessionManager.Use(r))
}
