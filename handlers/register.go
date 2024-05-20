package handlers

import "net/http"

func Register(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(201)
	w.Write([]byte("register"))
}
