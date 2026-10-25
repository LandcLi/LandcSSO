package cmd

import (
	"context"

	"github.com/LandcLi/landc-go/frame/pkg/cmd"
	"github.com/LandcLi/landc-go/frame/pkg/web"

	"github.com/LandcLi/LandcSSO/serverlib"
)

// Main 独立部署入口。
// 装配细节（建表、种子数据、用户中心接入、中间件与路由）全部收敛在 serverlib，
// 与「被其他服务嵌入」时走同一套装配逻辑，避免两种部署形态行为漂移。
var Main = cmd.NewCommand("main", "start SSO server", func(ctx context.Context, parser *cmd.Parser) error {
	server := web.New()
	if err := serverlib.RegisterToRouter(server); err != nil {
		return err
	}
	return server.RunWithContext(ctx)
})
