package main

import (
	"log"
	"os"

	"oidc-test-client/internal/app"
	"oidc-test-client/web"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = "config.json"
	}

	srv := app.New(app.Options{
		StaticFS:   web.Static,
		ConfigFile: configFile,
	})

	addr := ":" + port
	log.Printf("Starting OIDC test client on %s", addr)
	if err := srv.Start(addr); err != nil {
		log.Fatal(err)
	}
}
