package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/LandcLi/LandcSSO/internal/model"
	"github.com/LandcLi/LandcSSO/internal/repository"
	"github.com/LandcLi/LandcSSO/pkg/config"
	"github.com/LandcLi/LandcSSO/pkg/logger"
)

// ClientService 客户端服务
type ClientService struct {
	clientRepo *repository.ClientRepository
	config     *config.Config
}

// NewClientService 创建客户端服务实例
func NewClientService(clientRepo *repository.ClientRepository, config *config.Config) *ClientService {
	return &ClientService{
		clientRepo: clientRepo,
		config:     config,
	}
}

// List 获取客户端列表
func (s *ClientService) List(req *model.ClientListRequest) (*model.ClientListResponse, error) {
	ctx := context.Background()

	// 获取客户端列表
	clients, total, err := s.clientRepo.List(req.Page, req.PageSize)
	if err != nil {
		logger.Errorf(ctx, "获取客户端列表失败: %v", err)
		return nil, err
	}

	// 转换为响应格式
	clientResponses := make([]model.ClientResponse, len(clients))
	for i, client := range clients {
		clientResponses[i] = *client.ToResponse()
	}

	return &model.ClientListResponse{
		List:     clientResponses,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}, nil
}

// Create 创建客户端
func (s *ClientService) Create(req *model.ClientCreateRequest) (*model.ClientResponse, error) {
	ctx := context.Background()

	// 生成客户端ID和密钥
	clientID := generateClientID()
	clientSecret := generateClientSecret()

	// 序列化RedirectURIs
	redirectURIsJSON, err := json.Marshal(req.RedirectURIs)
	if err != nil {
		logger.Errorf(ctx, "序列化RedirectURIs失败: %v", err)
		return nil, err
	}

	// 序列化GrantTypes
	grantTypesJSON, err := json.Marshal(req.GrantTypes)
	if err != nil {
		logger.Errorf(ctx, "序列化GrantTypes失败: %v", err)
		return nil, err
	}

	// 序列化ResponseTypes
	responseTypesJSON, err := json.Marshal(req.ResponseTypes)
	if err != nil {
		logger.Errorf(ctx, "序列化ResponseTypes失败: %v", err)
		return nil, err
	}

	// 创建客户端
	client := &model.Client{
		ClientID:                 clientID,
		ClientSecret:             clientSecret,
		Name:                     req.Name,
		RedirectURIs:             string(redirectURIsJSON),
		Scope:                    req.Scope,
		GrantTypes:               string(grantTypesJSON),
		ResponseTypes:            string(responseTypesJSON),
		TokenEndpointAuthMethod:  req.TokenEndpointAuthMethod,
		Status:                   1,
	}

	// 保存客户端
	client, err = s.clientRepo.Create(client)
	if err != nil {
		logger.Errorf(ctx, "创建客户端失败: %v", err)
		return nil, err
	}

	return client.ToResponse(), nil
}

// Update 更新客户端
func (s *ClientService) Update(req *model.ClientUpdateRequest) (*model.ClientResponse, error) {
	ctx := context.Background()

	// 查找客户端
	client, err := s.clientRepo.FindByID(req.ID)
	if err != nil {
		logger.Errorf(ctx, "查找客户端失败: %v", err)
		return nil, errors.New("客户端不存在")
	}

	// 更新客户端信息
	if req.Name != "" {
		client.Name = req.Name
	}

	if len(req.RedirectURIs) > 0 {
		redirectURIsJSON, err := json.Marshal(req.RedirectURIs)
		if err != nil {
			logger.Errorf(ctx, "序列化RedirectURIs失败: %v", err)
			return nil, err
		}
		client.RedirectURIs = string(redirectURIsJSON)
	}

	if req.Scope != "" {
		client.Scope = req.Scope
	}

	if len(req.GrantTypes) > 0 {
		grantTypesJSON, err := json.Marshal(req.GrantTypes)
		if err != nil {
			logger.Errorf(ctx, "序列化GrantTypes失败: %v", err)
			return nil, err
		}
		client.GrantTypes = string(grantTypesJSON)
	}

	if len(req.ResponseTypes) > 0 {
		responseTypesJSON, err := json.Marshal(req.ResponseTypes)
		if err != nil {
			logger.Errorf(ctx, "序列化ResponseTypes失败: %v", err)
			return nil, err
		}
		client.ResponseTypes = string(responseTypesJSON)
	}

	if req.TokenEndpointAuthMethod != "" {
		client.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}

	if req.Status != 0 {
		client.Status = req.Status
	}

	// 保存更新
	client, err = s.clientRepo.Update(client)
	if err != nil {
		logger.Errorf(ctx, "更新客户端失败: %v", err)
		return nil, err
	}

	return client.ToResponse(), nil
}

// Delete 删除客户端
func (s *ClientService) Delete(req *model.ClientDeleteRequest) error {
	ctx := context.Background()

	// 查找客户端
	_, err := s.clientRepo.FindByID(req.ID)
	if err != nil {
		logger.Errorf(ctx, "查找客户端失败: %v", err)
		return errors.New("客户端不存在")
	}

	// 删除客户端
	err = s.clientRepo.Delete(req.ID)
	if err != nil {
		logger.Errorf(ctx, "删除客户端失败: %v", err)
		return err
	}

	return nil
}

// GetByClientID 根据ClientID获取客户端
func (s *ClientService) GetByClientID(clientID string) (*model.Client, error) {
	ctx := context.Background()

	// 查找客户端
	client, err := s.clientRepo.FindByClientID(clientID)
	if err != nil {
		logger.Errorf(ctx, "查找客户端失败: %v", err)
		return nil, err
	}

	return client, nil
}

// generateClientID 生成客户端ID
func generateClientID() string {
	ctx := context.Background()
	// 生成8位随机字符串
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	clientID := fmt.Sprintf("client_%s", string(b))
	logger.Infof(ctx, "生成客户端ID: %s", clientID)
	return clientID
}

// generateClientSecret 生成客户端密钥
func generateClientSecret() string {
	ctx := context.Background()
	// 生成32位随机字符串
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 32)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	clientSecret := fmt.Sprintf("secret_%s", string(b))
	logger.Infof(ctx, "生成客户端密钥: %s", clientSecret)
	return clientSecret
}
