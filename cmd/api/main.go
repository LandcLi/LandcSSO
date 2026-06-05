package main

import (
	"context"
	"log"

	_ "github.com/LandcLi/LandcSSO/internal/controller/auth"
	_ "github.com/LandcLi/LandcSSO/internal/controller/client"
	_ "github.com/LandcLi/LandcSSO/internal/daoimpl/audit"
	_ "github.com/LandcLi/LandcSSO/internal/daoimpl/client"
	_ "github.com/LandcLi/LandcSSO/internal/daoimpl/monitor"
	_ "github.com/LandcLi/LandcSSO/internal/daoimpl/token"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/audit"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/auth"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/client"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/key"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/monitor"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/session"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/third_party"
	"github.com/LandcLi/LandcSSO/internal/cmd"
)

func main() {
	if err := cmd.Main.Run(context.Background()); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
