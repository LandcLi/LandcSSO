package service

import (
	v1 "github.com/LandcLi/LandcSSO/api/client/v1"
	"github.com/LandcLi/LandcSSO/model"
)

type clientService interface {
	List(req *v1.ClientListRequest) (*v1.ClientListResponse, error)
	Create(req *v1.ClientCreateRequest) (*v1.ClientResponse, error)
	Update(req *v1.ClientUpdateRequest) (*v1.ClientResponse, error)
	Delete(req *v1.ClientDeleteRequest) error
	GetByClientID(clientID string) (*model.Client, error)
}

var clientServiceImpl clientService

func RegisterClientServiceImpl(impl clientService) {
	clientServiceImpl = impl
}

func GetClientService() clientService {
	return clientServiceImpl
}
