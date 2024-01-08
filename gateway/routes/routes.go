package routes

import (
	"github.com/go-chi/chi/v5"

	"github.com/sonrhq/identity/gateway/handlers"
)

func IdentityRoutes() chi.Router {
    r := chi.NewRouter()
    bookHandler := handlers.IdentityHandler{}
    r.Get("/", bookHandler.ViewPage)
    r.Get("/{id}", bookHandler.GetBooks)
    r.Put("/{id}", bookHandler.UpdateBook)
    r.Delete("/{id}", bookHandler.DeleteBook)
    return r
}
