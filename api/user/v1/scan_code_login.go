package v1

// VerifyScanCodeLoginRequest 验证扫码登录请求结构
type VerifyScanCodeLoginRequest struct {
	QrcodeID string `json:"qrcode_id" binding:"required"`
	UserID   uint   `json:"user_id" binding:"required"`
}

// CompleteScanCodeLoginRequest 完成扫码登录请求结构
type CompleteScanCodeLoginRequest struct {
	QrcodeID string `json:"qrcode_id" binding:"required"`
}
