package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type ClientDeleteRequest struct {
	meta.Meta `path:"/client/delete" method:"DELETE"`
	ID        uint `json:"id" binding:"required"`
}
