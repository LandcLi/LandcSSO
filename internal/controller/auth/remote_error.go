package auth

import (
	"encoding/json"
	"regexp"

	"github.com/LandcLi/landc-go/api/core"
)

// remoteServiceErrPattern 匹配 LUM SDK 远程调用返回的错误格式：
// "remote service returned status 404: {\"code\":40400,\"message\":\"user not found\"}"
var remoteServiceErrPattern = regexp.MustCompile(`remote service returned status \d+: (\{.*\})`)

// wrapRemoteError 解析 LUM SDK 远程调用错误，透传业务错误码与消息。
// landc-go 远程网关将远端业务错误包装为普通字符串 error，这里还原为 *core.Error，
// 使 SSO 能将 LUM 的业务错误码（40000/40400/40100 等）正确透传给调用方。
func wrapRemoteError(err error) error {
	if err == nil {
		return nil
	}
	m := remoteServiceErrPattern.FindStringSubmatch(err.Error())
	if len(m) == 2 {
		var resp struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal([]byte(m[1]), &resp) == nil && resp.Code != 0 {
			return core.NewError(core.ErrorCode(resp.Code), resp.Message)
		}
	}
	return err
}
