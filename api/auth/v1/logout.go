package v1

// LogoutRequest 登出请求结构
type LogoutRequest struct {
	Token    string `json:"token"`
	ClientID string `json:"client_id"`
}
