package api

import (
	"github.com/LandcLi/LandcSSO/api/auth"
	"github.com/LandcLi/LandcSSO/api/client"
	"github.com/LandcLi/landc-go/frame/pkg/web"
)

// RegisterDefaultRoutes registers all routes using Web Server.
func RegisterDefaultRoutes(server *web.Server) {
	if err := server.RegisterHandler(auth.GetAuthController()); err != nil {
		panic(err)
	}
	if err := server.RegisterHandler(client.GetClientController()); err != nil {
		panic(err)
	}
}
