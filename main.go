package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Tigraqt/ibkr-sim-backend/config"
	"github.com/Tigraqt/ibkr-sim-backend/handlers"
	"github.com/Tigraqt/ibkr-sim-backend/models"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	port := os.Getenv("PORT")

	config.ConnectDatabase()

	err := config.DB.AutoMigrate(&models.User{})
	if err != nil {
		log.Fatal("Failed to migrate database: ", err)
	}

	mux := http.NewServeMux()
	apiMux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, "Welcome to the home page!")
	})

	apiMux.HandleFunc("POST /register", handlers.Make(handlers.Register))
	apiMux.HandleFunc("POST /login", handlers.Login)

	mux.Handle("/api/", http.StripPrefix("/api", apiMux))

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Server is running on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())
}
