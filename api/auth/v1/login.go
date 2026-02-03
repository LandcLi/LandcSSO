package v1

type LoginRequest struct {
	Identifier   string `json:"identifier" binding:"required,min=3,max=50"`
	AuthCode     string `json:"verifyCode" binding:"required,len=6"` //第三方登陆时为openid,sso系统获取code、access_token然后再调用此接口
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	VerifyType   string `json:"verifyType" binding:"required,oneof=EMAIL PHONE USERNAME WECHAT GITHUB ALIPAY DINGTALK"`
	AuthType     string `json:"authType" binding:"required,oneof=PASSWORD VERIFY_CODE THIRD_PARTY"`
}
