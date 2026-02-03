package v1

// IntrospectRequest 令牌验证请求结构
type IntrospectRequest struct {
	Token        string `json:"token" binding:"required"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
