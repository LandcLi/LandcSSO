package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	v1 "github.com/LandcLi/LandcSSO/api/client/v1"
	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/LandcSSO/utility/security"
	"github.com/LandcLi/landc-go/log/facade"
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

	clients, total, err := dao.GetClientDao().List(req.Page, req.PageSize)
	if err != nil {
		facade.Errorf("获取客户端列表失败: %v", err)
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

	clientID := GenerateClientID()
	plainSecret := GenerateClientSecret()

	// 客户端密钥以 bcrypt 哈希存储，明文仅在创建时返回一次
	hashedSecret, err := security.HashSecret(plainSecret)
	if err != nil {
		facade.Errorf("客户端密钥哈希失败: %v", err)
		return nil, err
	}

	redirectURIsJSON, err := json.Marshal(req.RedirectURIs)
	if err != nil {
		facade.Errorf("序列化RedirectURIs失败: %v", err)
		return nil, err
	}

	grantTypesJSON, err := json.Marshal(req.GrantTypes)
	if err != nil {
		facade.Errorf("序列化GrantTypes失败: %v", err)
		return nil, err
	}

	responseTypesJSON, err := json.Marshal(req.ResponseTypes)
	if err != nil {
		facade.Errorf("序列化ResponseTypes失败: %v", err)
		return nil, err
	}

	client := &model.Client{
		ClientID:                clientID,
		ClientSecret:            hashedSecret,
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
		facade.Errorf("创建客户端失败: %v", err)
		return nil, err
	}

	resp := client.ToResponse()
	resp.ClientSecret = plainSecret // 明文仅本次返回，之后不可再获取
	return resp, nil
}

func (s *clientServiceImpl) Update(req *v1.ClientUpdateRequest) (*v1.ClientResponse, error) {

	client, err := dao.GetClientDao().FindByID(req.ID)
	if err != nil {
		facade.Errorf("查找客户端失败: %v", err)
		return nil, errors.New("客户端不存在")
	}

	if req.Name != "" {
		client.Name = req.Name
	}

	if len(req.RedirectURIs) > 0 {
		redirectURIsJSON, err := json.Marshal(req.RedirectURIs)
		if err != nil {
			facade.Errorf("序列化RedirectURIs失败: %v", err)
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
			facade.Errorf("序列化GrantTypes失败: %v", err)
			return nil, err
		}
		client.GrantTypes = string(grantTypesJSON)
	}

	if len(req.ResponseTypes) > 0 {
		responseTypesJSON, err := json.Marshal(req.ResponseTypes)
		if err != nil {
			facade.Errorf("序列化ResponseTypes失败: %v", err)
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
		facade.Errorf("更新客户端失败: %v", err)
		return nil, err
	}

	return client.ToResponse(), nil
}

func (s *clientServiceImpl) Delete(req *v1.ClientDeleteRequest) error {

	_, err := dao.GetClientDao().FindByID(req.ID)
	if err != nil {
		facade.Errorf("查找客户端失败: %v", err)
		return errors.New("客户端不存在")
	}

	err = dao.GetClientDao().Delete(req.ID)
	if err != nil {
		facade.Errorf("删除客户端失败: %v", err)
		return err
	}

	return nil
}

func (s *clientServiceImpl) GetByClientID(clientID string) (*model.Client, error) {

	client, err := dao.GetClientDao().FindByClientID(clientID)
	if err != nil {
		facade.Errorf("查找客户端失败: %v", err)
		return nil, err
	}

	return client, nil
}

func GenerateClientID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 8)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = charset[0]
			continue
		}
		b[i] = charset[n.Int64()]
	}
	clientID := fmt.Sprintf("client_%s", string(b))
	facade.Infof("生成客户端ID: %s", clientID)
	return clientID
}

func GenerateClientSecret() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = charset[0]
			continue
		}
		b[i] = charset[n.Int64()]
	}
	clientSecret := fmt.Sprintf("secret_%s", string(b))
	facade.Infof("生成客户端密钥: %s", clientSecret)
	return clientSecret
}
