package client

import (
	"context"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/LandcSSO/utility/logger"
	"gorm.io/gorm"
)

type clientDaoImpl struct {
	db *gorm.DB
}

func NewClientDaoImpl() *clientDaoImpl {
	return &clientDaoImpl{
		db: config.GetDB(),
	}
}

func init() {
	if dao.GetClientDao() == nil {
		dao.RegisterClientDaoImpl(NewClientDaoImpl())
	}
}

func (r *clientDaoImpl) FindByID(id uint) (*model.Client, error) {
	ctx := context.Background()
	var client model.Client
	err := r.db.First(&client, id).Error
	if err != nil {
		logger.Errorf(ctx, "根据ID查找客户端失败: %v", err)
		return nil, err
	}
	return &client, nil
}

func (r *clientDaoImpl) FindByClientID(clientID string) (*model.Client, error) {
	ctx := context.Background()
	var client model.Client
	err := r.db.Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		logger.Errorf(ctx, "根据ClientID查找客户端失败: %v", err)
		return nil, err
	}
	return &client, nil
}

func (r *clientDaoImpl) List(page, pageSize int) ([]model.Client, int64, error) {
	ctx := context.Background()
	var clients []model.Client
	var total int64

	err := r.db.Model(&model.Client{}).Count(&total).Error
	if err != nil {
		logger.Errorf(ctx, "计算客户端总数失败: %v", err)
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = r.db.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&clients).Error
	if err != nil {
		logger.Errorf(ctx, "获取客户端列表失败: %v", err)
		return nil, 0, err
	}

	return clients, total, nil
}

func (r *clientDaoImpl) Create(client *model.Client) (*model.Client, error) {
	ctx := context.Background()

	err := r.db.Create(client).Error
	if err != nil {
		logger.Errorf(ctx, "创建客户端失败: %v", err)
		return nil, err
	}

	return client, nil
}

func (r *clientDaoImpl) Update(client *model.Client) (*model.Client, error) {
	ctx := context.Background()

	err := r.db.Save(client).Error
	if err != nil {
		logger.Errorf(ctx, "更新客户端失败: %v", err)
		return nil, err
	}

	return client, nil
}

func (r *clientDaoImpl) Delete(id uint) error {
	ctx := context.Background()
	err := r.db.Delete(&model.Client{}, id).Error
	if err != nil {
		logger.Errorf(ctx, "删除客户端失败: %v", err)
		return err
	}
	return nil
}
