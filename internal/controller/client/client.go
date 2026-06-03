package client

import (
	"context"

	clientApi "github.com/LandcLi/LandcSSO/api/client"
	v1 "github.com/LandcLi/LandcSSO/api/client/v1"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/landc-go/frame/pkg/di"
)

func init() {
	di.Provide[clientApi.ClientController]("client.controller", NewClientController())
}

type clientController struct {
}

func NewClientController() *clientController {
	return &clientController{}
}

func (c *clientController) ClientCreate(ctx context.Context, req *v1.ClientCreateRequest) (*v1.ClientResponse, error) {
	return service.GetClientService().Create(req)
}

func (c *clientController) ClientDelete(ctx context.Context, req *v1.ClientDeleteRequest) error {
	return service.GetClientService().Delete(req)
}

func (c *clientController) ClientList(ctx context.Context, req *v1.ClientListRequest) (*v1.ClientListResponse, error) {
	return service.GetClientService().List(req)
}

func (c *clientController) ClientUpdate(ctx context.Context, req *v1.ClientUpdateRequest) (*v1.ClientResponse, error) {
	return service.GetClientService().Update(req)
}
