package identity

import (
	"github.com/go-chi/chi/v5"

	"github.com/sonrhq/identity/gateway/routes"
)

func RegisterGateway(mux *chi.Mux) {
    mux.Mount("/identity", routes.IdentityRoutes())
}
