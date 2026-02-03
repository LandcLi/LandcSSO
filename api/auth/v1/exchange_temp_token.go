package v1

// ExchangeTempTokenRequest 兑换临时令牌请求结构
type ExchangeTempTokenRequest struct {
	TempToken        string `json:"temp_token" binding:"required"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
}
