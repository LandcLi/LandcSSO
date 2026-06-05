package main

import (
	"context"
	"log"

	_ "github.com/LandcLi/LandcSSO/internal"
	"github.com/LandcLi/LandcSSO/internal/cmd"
)

func main() {
	if err := cmd.Main.Run(context.Background()); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
