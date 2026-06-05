package cmd

import (
	"context"

	"github.com/LandcLi/LandcSSO/api"
	"github.com/LandcLi/LandcSSO/middleware"
	"github.com/LandcLi/landc-go/frame/pkg/cmd"
	"github.com/LandcLi/landc-go/frame/pkg/web"
	userapi "github.com/LandcLi/LandcUserManager/api/user"
)

// Main is the main application command.
// cmd.Main.Run(ctx) handles bootstrap lifecycle + signal handling.
var Main = cmd.NewCommand("main", "start HTTP server", func(ctx context.Context, parser *cmd.Parser) error {
	server := web.NewServer(nil)

	// Add SSO middleware
	server.Engine().Use(middleware.Cors())
	server.Engine().Use(middleware.CtxEnricherMiddleware())
	server.Engine().Use(middleware.RequestLogger())

	// LandcUserManager - remote mode
	userapi.UserGateway.ProvideRemote("http://user-service:8080")

	// Register SSO routes
	api.RegisterDefaultRoutes(server)

	return server.RunWithContext(ctx)
})
