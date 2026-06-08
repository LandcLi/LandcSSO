package client

import (
	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/landc-go/log/facade"
	"gorm.io/gorm"
)

type clientDaoImpl struct{}

func NewClientDaoImpl() *clientDaoImpl {
	return &clientDaoImpl{}
}

func (r *clientDaoImpl) getDB() *gorm.DB {
	return config.GetDB()
}

func init() {
	if dao.GetClientDao() == nil {
		dao.RegisterClientDaoImpl(NewClientDaoImpl())
	}
}

func (r *clientDaoImpl) FindByID(id uint) (*model.Client, error) {
	var client model.Client
	err := r.getDB().First(&client, id).Error
	if err != nil {
		facade.Errorf("根据ID查找客户端失败: %v", err)
		return nil, err
	}
	return &client, nil
}

func (r *clientDaoImpl) FindByClientID(clientID string) (*model.Client, error) {
	var client model.Client
	err := r.getDB().Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		facade.Errorf("根据ClientID查找客户端失败: %v", err)
		return nil, err
	}
	return &client, nil
}

func (r *clientDaoImpl) List(page, pageSize int) ([]model.Client, int64, error) {
	var clients []model.Client
	var total int64

	err := r.getDB().Model(&model.Client{}).Count(&total).Error
	if err != nil {
		facade.Errorf("计算客户端总数失败: %v", err)
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = r.getDB().Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&clients).Error
	if err != nil {
		facade.Errorf("获取客户端列表失败: %v", err)
		return nil, 0, err
	}

	return clients, total, nil
}

func (r *clientDaoImpl) Create(client *model.Client) (*model.Client, error) {
	err := r.getDB().Create(client).Error
	if err != nil {
		facade.Errorf("创建客户端失败: %v", err)
		return nil, err
	}
	return client, nil
}

func (r *clientDaoImpl) Update(client *model.Client) (*model.Client, error) {
	err := r.getDB().Save(client).Error
	if err != nil {
		facade.Errorf("更新客户端失败: %v", err)
		return nil, err
	}
	return client, nil
}

func (r *clientDaoImpl) Delete(id uint) error {
	err := r.getDB().Delete(&model.Client{}, id).Error
	if err != nil {
		facade.Errorf("删除客户端失败: %v", err)
		return err
	}
	return nil
}
