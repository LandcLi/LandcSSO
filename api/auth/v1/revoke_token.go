package v1

// RevokeTokenRequest 撤销令牌请求结构
type RevokeTokenRequest struct {
	Token        string `json:"token" binding:"required"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
