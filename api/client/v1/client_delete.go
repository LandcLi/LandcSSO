package v1

// ClientDeleteRequest 删除客户端请求
type ClientDeleteRequest struct {
	ID uint `json:"id" binding:"required"`
}
