package service

import (
	"github.com/LandcLi/LandcSSO/model"
)

type clientService interface {
	List(req *model.ClientListRequest) (*model.ClientListResponse, error)
	Create(req *model.ClientCreateRequest) (*model.ClientResponse, error)
	Update(req *model.ClientUpdateRequest) (*model.ClientResponse, error)
	Delete(req *model.ClientDeleteRequest) error
	GetByClientID(clientID string) (*model.Client, error)
}

var clientServiceImpl clientService

func RegisterClientServiceImpl(impl clientService) {
	clientServiceImpl = impl
}

func GetClientService() clientService {
	return clientServiceImpl
}
