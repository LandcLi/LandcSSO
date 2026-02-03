package dao

import (
	"github.com/LandcLi/LandcSSO/model"
)

type clientDao interface {
	FindByID(id uint) (*model.Client, error)
	FindByClientID(clientID string) (*model.Client, error)
	List(page, pageSize int) ([]model.Client, int64, error)
	Create(client *model.Client) (*model.Client, error)
	Update(client *model.Client) (*model.Client, error)
	Delete(id uint) error
}

var clientDaoImpl clientDao

func RegisterClientDaoImpl(impl clientDao) {
	clientDaoImpl = impl
}

func GetClientDao() clientDao {
	return clientDaoImpl
}
