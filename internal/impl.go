package internal

import (
	_ "github.com/LandcLi/LandcSSO/internal/dao_impl/audit"
	_ "github.com/LandcLi/LandcSSO/internal/dao_impl/client"
	_ "github.com/LandcLi/LandcSSO/internal/dao_impl/monitor"
	_ "github.com/LandcLi/LandcSSO/internal/dao_impl/token"

	_ "github.com/LandcLi/LandcSSO/internal/service_impl/audit"
	_ "github.com/LandcLi/LandcSSO/internal/service_impl/auth"
	_ "github.com/LandcLi/LandcSSO/internal/service_impl/client"
	_ "github.com/LandcLi/LandcSSO/internal/service_impl/key"
	_ "github.com/LandcLi/LandcSSO/internal/service_impl/monitor"
	_ "github.com/LandcLi/LandcSSO/internal/service_impl/session"
	_ "github.com/LandcLi/LandcSSO/internal/service_impl/third_party"

	_ "github.com/LandcLi/LandcSSO/internal/controller/auth"
	_ "github.com/LandcLi/LandcSSO/internal/controller/client"
)
