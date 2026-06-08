package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type LoginRequest struct {
	meta.Meta   `path:"/auth/login" method:"POST"`
	Identifier  string `json:"identifier" binding:"required,min=3,max=50"`
	AuthCode    string `json:"verifyCode" binding:"required"`
	VerifyType  string `json:"verifyType" binding:"required,oneof=EMAIL PHONE USERNAME WECHAT GITHUB ALIPAY DINGTALK"`
	AuthType    string `json:"authType" binding:"required,oneof=PASSWORD VERIFY_CODE THIRD_PARTY"`
	RedirectURI string `json:"redirect_uri"`
}
