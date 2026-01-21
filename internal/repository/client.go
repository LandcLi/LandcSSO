package repository

import (
	"context"

	"github.com/LandcLi/LandcSSO/internal/model"
	"github.com/LandcLi/LandcSSO/pkg/logger"
	"gorm.io/gorm"
)

// ClientRepository 客户端仓库
type ClientRepository struct {
	db *gorm.DB
}

// NewClientRepository 创建客户端仓库实例
func NewClientRepository(db *gorm.DB) *ClientRepository {
	return &ClientRepository{
		db: db,
	}
}

// FindByID 根据ID查找客户端
func (r *ClientRepository) FindByID(id uint) (*model.Client, error) {
	ctx := context.Background()
	var client model.Client
	err := r.db.First(&client, id).Error
	if err != nil {
		logger.Errorf(ctx, "根据ID查找客户端失败: %v", err)
		return nil, err
	}
	return &client, nil
}

// FindByClientID 根据ClientID查找客户端
func (r *ClientRepository) FindByClientID(clientID string) (*model.Client, error) {
	ctx := context.Background()
	var client model.Client
	err := r.db.Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		logger.Errorf(ctx, "根据ClientID查找客户端失败: %v", err)
		return nil, err
	}
	return &client, nil
}

// List 获取客户端列表
func (r *ClientRepository) List(page, pageSize int) ([]model.Client, int64, error) {
	ctx := context.Background()
	var clients []model.Client
	var total int64

	// 计算总数
	err := r.db.Model(&model.Client{}).Count(&total).Error
	if err != nil {
		logger.Errorf(ctx, "计算客户端总数失败: %v", err)
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	err = r.db.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&clients).Error
	if err != nil {
		logger.Errorf(ctx, "获取客户端列表失败: %v", err)
		return nil, 0, err
	}

	return clients, total, nil
}

// Create 创建客户端
func (r *ClientRepository) Create(client *model.Client) (*model.Client, error) {
	ctx := context.Background()

	// 创建客户端
	err := r.db.Create(client).Error
	if err != nil {
		logger.Errorf(ctx, "创建客户端失败: %v", err)
		return nil, err
	}

	return client, nil
}

// Update 更新客户端
func (r *ClientRepository) Update(client *model.Client) (*model.Client, error) {
	ctx := context.Background()

	// 更新客户端
	err := r.db.Save(client).Error
	if err != nil {
		logger.Errorf(ctx, "更新客户端失败: %v", err)
		return nil, err
	}

	return client, nil
}

// Delete 删除客户端
func (r *ClientRepository) Delete(id uint) error {
	ctx := context.Background()
	err := r.db.Delete(&model.Client{}, id).Error
	if err != nil {
		logger.Errorf(ctx, "删除客户端失败: %v", err)
		return err
	}
	return nil
}
