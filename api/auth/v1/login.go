package v1

type LoginRequest struct {
	Identifier  string `json:"identifier" binding:"required,min=3,max=50"`
	AuthCode    string `json:"verifyCode" binding:"required,len=6"` // 验证码 OR 密码，在第三方登陆的场景中为第三方跳转回来的code
	VerifyType  string `json:"verifyType" binding:"required,oneof=EMAIL PHONE USERNAME WECHAT GITHUB ALIPAY DINGTALK"`
	AuthType    string `json:"authType" binding:"required,oneof=PASSWORD VERIFY_CODE THIRD_PARTY"`
	RedirectURI string `json:"redirect_uri"` // 第三方登录时需要的redirect_uri
}
