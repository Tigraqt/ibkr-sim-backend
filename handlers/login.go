package handlers

import "net/http"

func Login(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("login"))
}
