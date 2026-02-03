package v1

// RefreshTokenRequest 刷新令牌请求结构
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}
