package handlers

import (
	"net/http"

	"github.com/sonrhq/identity/gateway/templates/components"
)

type IdentityHandler struct {
}

func (b IdentityHandler) ViewPage(w http.ResponseWriter, r *http.Request) {
	err := components.Page(0,1).Render(r.Context(), w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}


func (b IdentityHandler) ListBooks(w http.ResponseWriter, r *http.Request)  {}
func (b IdentityHandler) GetBooks(w http.ResponseWriter, r *http.Request)   {}
func (b IdentityHandler) CreateBook(w http.ResponseWriter, r *http.Request) {}
func (b IdentityHandler) UpdateBook(w http.ResponseWriter, r *http.Request) {}
func (b IdentityHandler) DeleteBook(w http.ResponseWriter, r *http.Request) {}
