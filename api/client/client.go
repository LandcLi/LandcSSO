package client

import (
	"context"

	v1 "github.com/LandcLi/LandcSSO/api/client/v1"
	"github.com/LandcLi/landc-go/frame/pkg/di"
)

// ClientController defines the OAuth client management interface.
type ClientController interface {
	ClientCreate(ctx context.Context, req *v1.ClientCreateRequest) (*v1.ClientResponse, error)
	ClientDelete(ctx context.Context, req *v1.ClientDeleteRequest) error
	ClientList(ctx context.Context, req *v1.ClientListRequest) (*v1.ClientListResponse, error)
	ClientUpdate(ctx context.Context, req *v1.ClientUpdateRequest) (*v1.ClientResponse, error)
}

// ClientGateway is the service gateway for client management.
var ClientGateway = di.NewGateway[ClientController]("client.controller")

// GetClientController returns the registered ClientController implementation.
func GetClientController() ClientController {
	return ClientGateway.Get()
}

// RegisterClientController registers a ClientController implementation.
func RegisterClientController(impl ClientController) {
	ClientGateway.Provide(impl)
}
