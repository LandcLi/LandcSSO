package serverlib

import (
	"encoding/json"
	"fmt"

	"github.com/LandcLi/landc-go/log/facade"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/LandcSSO/utility/security"
)

// Seed 写入首次启动所需的种子数据（目前为示例 OAuth 客户端）。
//
// 生产环境应保持 seed.enabled=false，改由管理接口创建客户端。
// 幂等：client_id 已存在时不做任何修改。
func Seed() error {
	cfg := config.GetConfig()
	if cfg == nil {
		return fmt.Errorf("serverlib: config not initialized")
	}
	if !cfg.Seed.Enabled {
		return nil
	}

	if _, err := dao.GetClientDao().FindByClientID(cfg.Seed.ClientID); err == nil {
		// 已存在，保持幂等
		return nil
	}

	hashedSecret, err := security.HashSecret(cfg.Seed.ClientSecret)
	if err != nil {
		return fmt.Errorf("serverlib: hash seed client secret: %w", err)
	}

	redirectURIs, err := json.Marshal(cfg.Seed.RedirectURIs)
	if err != nil {
		return fmt.Errorf("serverlib: marshal seed redirect uris: %w", err)
	}
	grantTypes, err := json.Marshal([]string{
		"authorization_code", "refresh_token", "client_credentials", "password",
	})
	if err != nil {
		return fmt.Errorf("serverlib: marshal seed grant types: %w", err)
	}
	responseTypes, err := json.Marshal([]string{"code"})
	if err != nil {
		return fmt.Errorf("serverlib: marshal seed response types: %w", err)
	}

	client := &model.Client{
		ClientID:                cfg.Seed.ClientID,
		ClientSecret:            hashedSecret,
		Name:                    "LandcSSO 示例客户端",
		RedirectURIs:            string(redirectURIs),
		Scope:                   cfg.Seed.Scope,
		GrantTypes:              string(grantTypes),
		ResponseTypes:           string(responseTypes),
		TokenEndpointAuthMethod: "client_secret_post",
		Status:                  1,
	}
	if _, err := dao.GetClientDao().Create(client); err != nil {
		return fmt.Errorf("serverlib: create seed client: %w", err)
	}

	facade.Warn("seeded default oauth client; 生产环境请关闭 seed.enabled 并改用管理接口创建客户端",
		facade.Field{Key: "client_id", Value: cfg.Seed.ClientID})
	return nil
}
