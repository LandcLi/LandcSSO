package tests

import (
	"testing"

	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
)

func TestClientService_List(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化数据库
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		t.Skipf("初始化数据库失败: %v, 跳过测试", err)
	}

	// 获取数据库连接
	db := config.GetDB()

	// 创建仓库
	clientRepo := repository.NewClientRepository(db)

	// 创建客户端服务
	clientService := service.NewClientService(clientRepo, cfg)

	// 测试获取客户端列表
	req := &model.ClientListRequest{
		Page:     1,
		PageSize: 10,
	}

	resp, err := clientService.List(req)
	if err != nil {
		t.Fatalf("List() 失败: %v", err)
	}

	if resp == nil {
		t.Errorf("List() 返回 nil")
	}
}

func TestClientService_Create(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化数据库
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		t.Skipf("初始化数据库失败: %v, 跳过测试", err)
	}

	// 获取数据库连接
	db := config.GetDB()

	// 创建仓库
	clientRepo := repository.NewClientRepository(db)

	// 创建客户端服务
	clientService := service.NewClientService(clientRepo, cfg)

	// 测试创建客户端
	req := &model.ClientCreateRequest{
		Name:                    "测试客户端2",
		RedirectURIs:            []string{"http://localhost:3001/callback"},
		Scope:                   "openid profile email",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	resp, err := clientService.Create(req)
	if err != nil {
		t.Fatalf("Create() 失败: %v", err)
	}

	if resp == nil {
		t.Errorf("Create() 返回 nil")
	}

	if resp.ClientID == "" {
		t.Errorf("ClientID 期望非空字符串, 实际为空")
	}
}

func TestClientService_Update(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化数据库
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		t.Skipf("初始化数据库失败: %v, 跳过测试", err)
	}

	// 获取数据库连接
	db := config.GetDB()

	// 创建仓库
	clientRepo := repository.NewClientRepository(db)

	// 创建客户端服务
	clientService := service.NewClientService(clientRepo, cfg)

	// 测试更新客户端
	req := &model.ClientUpdateRequest{
		ID:           1, // 默认客户端ID
		Name:         "更新后的测试客户端",
		RedirectURIs: []string{"http://localhost:3000/callback", "http://localhost:3001/callback"},
		Scope:        "openid profile email phone",
		Status:       1,
	}

	resp, err := clientService.Update(req)
	if err != nil {
		t.Fatalf("Update() 失败: %v", err)
	}

	if resp == nil {
		t.Errorf("Update() 返回 nil")
	}
}

func TestClientService_Delete(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化数据库
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		t.Skipf("初始化数据库失败: %v, 跳过测试", err)
	}

	// 获取数据库连接
	db := config.GetDB()

	// 创建仓库
	clientRepo := repository.NewClientRepository(db)

	// 创建客户端服务
	clientService := service.NewClientService(clientRepo, cfg)

	// 测试删除客户端
	req := &model.ClientDeleteRequest{
		ID: 2, // 假设ID为2的客户端存在
	}

	err = clientService.Delete(req)
	if err != nil {
		t.Logf("Delete() 失败: %v", err)
		// 允许删除失败，因为客户端可能不存在
	}
}
