package main

import (
	"context"
	"log"

	_ "github.com/LandcLi/LandcSSO/internal"
	"github.com/LandcLi/LandcSSO/internal/cmd"

	// LandcUserManager SDK proxy (init registers proxy factories for remote calls)
	_ "github.com/LandcLi/LandcUserManager/sdk"
)

func main() {
	if err := cmd.Main.Run(context.Background()); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
