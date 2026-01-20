package repository

import (
	"context"

	"github.com/LandcLi/LandcBranchGorm/pkg/dbmanager"
	"github.com/LandcLi/LandcSSO/internal/model"
	"github.com/LandcLi/LandcSSO/pkg/logger"
)

// ClientRepository 客户端仓库
type ClientRepository struct {
	dbmanager *dbmanager.DBManager
}

// NewClientRepository 创建客户端仓库实例
func NewClientRepository(dbmanager *dbmanager.DBManager) *ClientRepository {
	return &ClientRepository{
		dbmanager: dbmanager,
	}
}

// FindByID 根据ID查找客户端
func (r *ClientRepository) FindByID(id uint) (*model.Client, error) {
	ctx := context.Background()
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			logger.Errorf(ctx, "获取数据库连接失败: %v", err)
			return nil, err
		}
	}
	var client model.Client
	err = db.First(&client, id).Error
	if err != nil {
		logger.Errorf(ctx, "根据ID查找客户端失败: %v", err)
		return nil, err
	}
	return &client, nil
}

// FindByClientID 根据ClientID查找客户端
func (r *ClientRepository) FindByClientID(clientID string) (*model.Client, error) {
	ctx := context.Background()
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			logger.Errorf(ctx, "获取数据库连接失败: %v", err)
			return nil, err
		}
	}
	var client model.Client
	err = db.Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		logger.Errorf(ctx, "根据ClientID查找客户端失败: %v", err)
		return nil, err
	}
	return &client, nil
}

// List 获取客户端列表
func (r *ClientRepository) List(page, pageSize int) ([]model.Client, int64, error) {
	ctx := context.Background()
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			logger.Errorf(ctx, "获取数据库连接失败: %v", err)
			return nil, 0, err
		}
	}
	var clients []model.Client
	var total int64

	// 计算总数
	err = db.Model(&model.Client{}).Count(&total).Error
	if err != nil {
		logger.Errorf(ctx, "计算客户端总数失败: %v", err)
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	err = db.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&clients).Error
	if err != nil {
		logger.Errorf(ctx, "获取客户端列表失败: %v", err)
		return nil, 0, err
	}

	return clients, total, nil
}

// Create 创建客户端
func (r *ClientRepository) Create(client *model.Client) (*model.Client, error) {
	ctx := context.Background()
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		logger.Errorf(ctx, "获取数据库连接失败: %v", err)
		return nil, err
	}

	// 创建客户端
	err = db.Create(client).Error
	if err != nil {
		logger.Errorf(ctx, "创建客户端失败: %v", err)
		return nil, err
	}

	return client, nil
}

// Update 更新客户端
func (r *ClientRepository) Update(client *model.Client) (*model.Client, error) {
	ctx := context.Background()
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		logger.Errorf(ctx, "获取数据库连接失败: %v", err)
		return nil, err
	}

	// 更新客户端
	err = db.Save(client).Error
	if err != nil {
		logger.Errorf(ctx, "更新客户端失败: %v", err)
		return nil, err
	}

	return client, nil
}

// Delete 删除客户端
func (r *ClientRepository) Delete(id uint) error {
	ctx := context.Background()
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		logger.Errorf(ctx, "获取数据库连接失败: %v", err)
		return err
	}
	err = db.Delete(&model.Client{}, id).Error
	if err != nil {
		logger.Errorf(ctx, "删除客户端失败: %v", err)
		return err
	}
	return nil
}
