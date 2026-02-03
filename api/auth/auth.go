package auth

import (
	"context"
	"net/http"

	v1 "github.com/LandcLi/LandcSSO/api/auth/v1"
	"github.com/gin-gonic/gin"
)

var authControllerImpl authApi

type authApi interface {
	Login(ctx context.Context, req *v1.LoginRequest) (*v1.TokenResponse, error)
}

func RegisterAuthController(controller authApi) {
	authControllerImpl = controller
}

func GetAuthController() authApi {
	return authControllerImpl
}

func Login(c *gin.Context) {
	req := &v1.LoginRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	resp, err := authControllerImpl.Login(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}
