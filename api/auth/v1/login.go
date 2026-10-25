package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type LoginRequest struct {
	meta.Meta `path:"/auth/login" method:"POST"`
	// Identifier 标识：PASSWORD/VERIFY_CODE 模式必填；THIRD_PARTY 模式可为空（openId 由 LUM 从 access_token 换取）
	Identifier string `json:"identifier" binding:"omitempty,min=3,max=50"`
	// AuthCode 凭据：PASSWORD/VERIFY_CODE 模式必填；THIRD_PARTY 模式按 provider 约定（GitHub 可空，微信承载 openid）
	AuthCode    string `json:"verifyCode" binding:"omitempty"`
	VerifyType  string `json:"verifyType" binding:"required,oneof=EMAIL PHONE USERNAME WECHAT GITHUB ALIPAY DINGTALK"`
	AuthType    string `json:"authType" binding:"required,oneof=PASSWORD VERIFY_CODE THIRD_PARTY"`
	RedirectURI string `json:"redirect_uri"`
	// State 第三方登录回调时原样回传的 CSRF 防伪 state（THIRD_PARTY 模式必填）
	State string `json:"state"`
}
