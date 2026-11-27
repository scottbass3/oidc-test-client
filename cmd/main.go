package main

import (
	"log"
	"os"
	"strconv"
	"time"

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

	locked := false
	if v := os.Getenv("LOCKED"); v != "" {
		var err error
		if locked, err = strconv.ParseBool(v); err != nil {
			log.Fatalf("LOCKED=%q: want true or false", v)
		}
	}

	var sessionTTL time.Duration
	if v := os.Getenv("SESSION_TTL"); v != "" {
		var err error
		if sessionTTL, err = time.ParseDuration(v); err != nil || sessionTTL <= 0 {
			log.Fatalf("SESSION_TTL=%q: want a duration such as 12h or 30m", v)
		}
	}

	var webURL string
	if v := os.Getenv("WEB_URL"); v != "" {
		var err error
		if webURL, err = app.ParseWebURL(v); err != nil {
			log.Fatalf("WEB_URL=%q: %v", v, err)
		}
	}

	srv := app.New(app.Options{
		StaticFS:   web.Static,
		ConfigFile: configFile,
		Locked:     locked,
		SessionTTL: sessionTTL,
		WebURL:     webURL,
	})

	addr := ":" + port
	if locked {
		log.Printf("Locked mode: provider and client fixed by the environment, one session per browser")
	}
	if webURL != "" {
		log.Printf("Served at %s", webURL)
	}
	log.Printf("Starting OIDC test client on %s", addr)
	if err := srv.Start(addr); err != nil {
		log.Fatal(err)
	}
}
