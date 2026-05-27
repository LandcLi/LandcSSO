package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

	v1 "github.com/LandcLi/LandcSSO/api/client/v1"
	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/LandcSSO/utility/logger"
)

type clientServiceImpl struct {
	config *config.Config
}

func NewClientServiceImpl() *clientServiceImpl {
	return &clientServiceImpl{
		config: config.GetConfig(),
	}
}

func init() {
	if service.GetClientService() == nil {
		service.RegisterClientServiceImpl(NewClientServiceImpl())
	}
}

func (s *clientServiceImpl) List(req *v1.ClientListRequest) (*v1.ClientListResponse, error) {
	ctx := context.Background()

	clients, total, err := dao.GetClientDao().List(req.Page, req.PageSize)
	if err != nil {
		logger.Errorf(ctx, "获取客户端列表失败: %v", err)
		return nil, err
	}

	clientResponses := make([]v1.ClientResponse, len(clients))
	for i, client := range clients {
		clientResponses[i] = *client.ToResponse()
	}

	return &v1.ClientListResponse{
		List:     clientResponses,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}, nil
}

func (s *clientServiceImpl) Create(req *v1.ClientCreateRequest) (*v1.ClientResponse, error) {
	ctx := context.Background()

	clientID := generateClientID()
	clientSecret := generateClientSecret()

	redirectURIsJSON, err := json.Marshal(req.RedirectURIs)
	if err != nil {
		logger.Errorf(ctx, "序列化RedirectURIs失败: %v", err)
		return nil, err
	}

	grantTypesJSON, err := json.Marshal(req.GrantTypes)
	if err != nil {
		logger.Errorf(ctx, "序列化GrantTypes失败: %v", err)
		return nil, err
	}

	responseTypesJSON, err := json.Marshal(req.ResponseTypes)
	if err != nil {
		logger.Errorf(ctx, "序列化ResponseTypes失败: %v", err)
		return nil, err
	}

	client := &model.Client{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		Name:                    req.Name,
		RedirectURIs:            string(redirectURIsJSON),
		Scope:                   req.Scope,
		GrantTypes:              string(grantTypesJSON),
		ResponseTypes:           string(responseTypesJSON),
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Status:                  1,
	}

	client, err = dao.GetClientDao().Create(client)
	if err != nil {
		logger.Errorf(ctx, "创建客户端失败: %v", err)
		return nil, err
	}

	return client.ToResponse(), nil
}

func (s *clientServiceImpl) Update(req *v1.ClientUpdateRequest) (*v1.ClientResponse, error) {
	ctx := context.Background()

	client, err := dao.GetClientDao().FindByID(req.ID)
	if err != nil {
		logger.Errorf(ctx, "查找客户端失败: %v", err)
		return nil, errors.New("客户端不存在")
	}

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

	client, err = dao.GetClientDao().Update(client)
	if err != nil {
		logger.Errorf(ctx, "更新客户端失败: %v", err)
		return nil, err
	}

	return client.ToResponse(), nil
}

func (s *clientServiceImpl) Delete(req *v1.ClientDeleteRequest) error {
	ctx := context.Background()

	_, err := dao.GetClientDao().FindByID(req.ID)
	if err != nil {
		logger.Errorf(ctx, "查找客户端失败: %v", err)
		return errors.New("客户端不存在")
	}

	err = dao.GetClientDao().Delete(req.ID)
	if err != nil {
		logger.Errorf(ctx, "删除客户端失败: %v", err)
		return err
	}

	return nil
}

func (s *clientServiceImpl) GetByClientID(clientID string) (*model.Client, error) {
	ctx := context.Background()

	client, err := dao.GetClientDao().FindByClientID(clientID)
	if err != nil {
		logger.Errorf(ctx, "查找客户端失败: %v", err)
		return nil, err
	}

	return client, nil
}

func generateClientID() string {
	ctx := context.Background()
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

func generateClientSecret() string {
	ctx := context.Background()
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
