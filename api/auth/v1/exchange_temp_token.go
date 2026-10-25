package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type ExchangeTempTokenRequest struct {
	meta.Meta    `path:"/auth/exchange-temp-token" method:"POST"`
	TempToken    string `json:"temp_token" binding:"required"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
