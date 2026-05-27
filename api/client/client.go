package client

import (
	"context"
	"net/http"

	v1 "github.com/LandcLi/LandcSSO/api/client/v1"
	"github.com/gin-gonic/gin"
)

var clientControllerImpl clientApi

type clientApi interface {
	ClientCreate(ctx context.Context, req *v1.ClientCreateRequest) (*v1.ClientResponse, error)
	ClientDelete(ctx context.Context, req *v1.ClientDeleteRequest) error
	ClientList(ctx context.Context, req *v1.ClientListRequest) (*v1.ClientListResponse, error)
	ClientUpdate(ctx context.Context, req *v1.ClientUpdateRequest) (*v1.ClientResponse, error)
}

func RegisterClientController(controller clientApi) {
	clientControllerImpl = controller
}

func GetClientController() clientApi {
	return clientControllerImpl
}

func ClientCreate(c *gin.Context) {
	req := &v1.ClientCreateRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	resp, err := clientControllerImpl.ClientCreate(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func ClientDelete(c *gin.Context) {
	req := &v1.ClientDeleteRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	err := clientControllerImpl.ClientDelete(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Client deleted successfully",
	})
}

func ClientList(c *gin.Context) {
	req := &v1.ClientListRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	resp, err := clientControllerImpl.ClientList(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func ClientUpdate(c *gin.Context) {
	req := &v1.ClientUpdateRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	resp, err := clientControllerImpl.ClientUpdate(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}
