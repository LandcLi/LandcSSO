# LandcSSO

LandcSSO是一个基于Go语言开发的单点登录（SSO）系统，支持OAuth 2.0和OpenID Connect协议，为企业应用提供统一的身份认证和授权服务。

## 功能特性

- **统一认证**：用户只需登录一次即可访问所有信任的应用
- **多协议支持**：实现了OAuth 2.0和OpenID Connect协议
- **多登录方式**：支持用户名/密码登录、邮箱验证码登录、第三方登录（微信、钉钉、GitHub、支付宝）
- **安全可靠**：JWT 令牌、PKCE、令牌轮换、CORS 白名单、客户端密钥 bcrypt 哈希存储
- **会话管理**：支持并发会话数限制，超过限制时自动撤销最旧的会话
- **完整登出**：支持完整的登出流程，包括通知所有已登录应用
- **高性能**：基于Go语言和Redis实现，支持高并发
- **可扩展**：模块化设计，易于扩展和集成
- **完整的SDK**：提供服务提供方（SP）SDK，方便应用集成
- **详细的文档**：完善的设计文档（[docs/design.md](docs/design.md)）和 API 文档（[docs/api.md](docs/api.md)）
- **单元测试**：覆盖随机令牌生成、RSA 密钥持久化、客户端密钥哈希、redirect_uri 校验、SSRF 防护等

> **功能状态说明**：扫码登录、生物识别登录、短信验证码、静默登录、异地登录检测目前为**规划中**（后端依赖 LandcUserManager，尚未实现）。

## 技术栈

- **后端**：Go 1.26 + Gin
- **框架**：`github.com/LandcLi/landc-go/frame`（配置 / DB / 缓存 / JWT / DI / Web / 健康检查 / 限流）
- **数据存储**：SQLite（默认，纯 Go 驱动，零外部依赖）｜MySQL（生产）｜Redis（可选，缺失时降级为进程内缓存）
- **认证协议**：OAuth 2.0 + OpenID Connect（授权码 + PKCE、客户端凭证、刷新令牌、密码、令牌自省、JWKS、Discovery）
- **用户数据**：LandcUserManager 统一维护，SSO 只持有 OAuth2/OIDC 自身数据

## 职责边界

| 系统 | 负责 |
| --- | --- |
| **LandcSSO**（本仓库） | 客户端注册、授权码、令牌签发与校验、会话、审计、OIDC 元数据 |
| **LandcUserManager** | 用户账号、密码、登录历史、可信设备、第三方账号绑定 |
| **LandcPermission** / **LandcOrg** | 角色权限、组织架构（由业务方按需接入） |

SSO 不直接读写用户表：用户相关操作全部经 `LandcUserManager`。
`user_manager.mode` 可选 `local`（进程内，单二进制部署）或 `remote`（独立部署，HTTP 调用），
两种模式下 SSO 的代码路径完全一致。

## 目录结构

```
cmd/api/              独立部署入口（thin main）
api/                  接口定义（请求/响应 + meta 路由标签）
internal/
  controller/         控制器
  service_impl/       业务实现（auth / client / key / session / third_party / audit / monitor）
  dao_impl/           数据访问实现
  middleware/         鉴权、CORS、上下文增强、请求日志
  cmd/                命令注册
model/                数据模型
serverlib/            库模式入口（RegisterToRouter / EnsureSchema / Seed）
service/              服务接口
dao/                  数据访问接口
utility/config/       类型化配置（log 段由框架解析）
utility/security/     密码/密钥哈希
sqls/                 MySQL 初始化脚本
docs/                 API 文档
tests/sqlite/         SQLite 端到端冒烟
```

## 快速开始

### 1. 环境准备

- Go 1.26 或更高版本
- 无需 MySQL / Redis：默认使用 SQLite + 进程内缓存

### 2. 生成配置并启动

```bash
cp config.example.yaml config.yaml
go run ./cmd/api
```

首次启动会自动：
1. 在 `data/sso.db` 创建 SQLite 库并建表（`database.auto_migrate: true`）
2. 写入示例 OAuth 客户端（`seed.enabled: true`）：
   - `client_id`: `landc-sso-demo`
   - `client_secret`: `landc-sso-demo-secret`
   - `redirect_uri`: `http://localhost:3000/callback`
3. 在进程内装配 LandcUserManager（`user_manager.mode: local`），用户表建在同一库中

服务在 `http://localhost:8080` 启动。

### 3. 验证

```bash
# 健康检查
curl http://127.0.0.1:8080/health

# OIDC Discovery（匿名可访问，返回扁平 JSON，不套 {code,message,data}）
curl http://127.0.0.1:8080/.well-known/openid-configuration

# 签名公钥（jwks_uri，匿名可访问）
curl http://127.0.0.1:8080/auth/jwks

# 当前令牌对应的用户信息（需 Bearer）
curl http://127.0.0.1:8080/auth/userinfo \
  -H "Authorization: Bearer <access_token>"

# 客户端凭证模式取令牌（响应为框架统一包装：{code,message,data}）
curl -X POST http://127.0.0.1:8080/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"client_credentials",
       "client_id":"landc-sso-demo",
       "client_secret":"landc-sso-demo-secret"}'
```

### 4. 切换到生产形态

```yaml
database:
  driver: "mysql"
  dsn: "user:password@tcp(127.0.0.1:3306)/sso_db?charset=utf8mb4&parseTime=True&loc=Local"
  auto_migrate: false        # 改用 sqls/init.sql

redis:
  addr: "redis:6379"         # 多实例部署必须配置

seed:
  enabled: false             # 改用 /client/create 管理接口创建客户端

user_manager:
  mode: "remote"             # LUM 独立部署时
  baseUrl: "http://lum:18081"
```

```bash
mysql -u root -p < sqls/init.sql
```

### 5. 作为库嵌入（进程内组合）

```go
server := web.New()
if err := serverlib.RegisterToRouter(server); err != nil {
    return err
}
return server.RunWithContext(ctx)
```

`RegisterToRouter` 内部完成建表、种子数据、用户中心接入、中间件与路由注册；
`internal/cmd` 的独立部署入口只是它的薄封装，两种形态行为一致。

## 响应约定

成功：HTTP 200 + `{"code":10000,"message":"success","data":{...}}`（框架统一包装，
`landc-go` 的 SDK / `di.Call` 会自动解包 `data`）。
失败：非 2xx + `{"code":<业务错误码>,"message":"..."}`。


## 使用示例

### 1. 授权码模式（Web应用）

1. **重定向到授权端点**：

```http
GET /auth/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid%20profile%20email&state=123456
```

2. **用户登录并授权**：

输入用户名和密码（默认管理员：admin/123456），点击授权按钮。

3. **获取授权码**：

服务会重定向到 `redirect_uri`，携带授权码和state参数：

```
http://localhost:3000/callback?code=authorization_code&state=123456
```

4. **交换令牌**：

使用授权码向令牌端点请求访问令牌：

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=authorization_code&client_id=test-client&client_secret=test-secret&redirect_uri=http://localhost:3000/callback
```

5. **获取用户信息**：

使用访问令牌获取用户信息：

```http
GET /auth/userinfo
Authorization: Bearer access_token
```

返回标准的扁平 JSON（不套 `{code,message,data}`）：

```json
{
  "sub": "1001",
  "preferred_username": "alice",
  "name": "Alice",
  "email": "alice@example.com",
  "email_verified": false,
  "phone_number": "13800000000",
  "picture": "https://.../avatar.png"
}
```

`sub` 是用户的稳定标识（十进制 userID），客户端应当把它当作本地账号的
外部主键长期保存。用户档案（邮箱/昵称/头像）由 LandcUserManager 提供，
SSO 只保管认证与令牌，不重复存一份。

> **能力边界（重要）**：本服务当前签发 `access_token` / `refresh_token`，
> **不签发 `id_token`**。因此它是「OAuth2 授权服务器 + OIDC 的 userinfo/jwks
> 子集」，而不是完整的 OIDC Provider。接入方请用 `authorization_code`
> 换令牌后调 `/auth/userinfo` 取用户信息，不要期待 ID Token 里的 claims。
> `/.well-known/openid-configuration` 如实声明了这一点（`response_types_supported`
> 只有 `code`）。

### 2. 刷新令牌模式

当访问令牌过期时，使用刷新令牌获取新的访问令牌：

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=refresh_token&client_id=test-client&client_secret=test-secret
```

### 3. 客户端凭证模式（服务间调用）

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=test-client&client_secret=test-secret&scope=api
```

### 4. 验证码登录

1. **发送验证码**：

```http
POST /user/send-verify-code
Content-Type: application/json

{
  "email": "user@example.com",
  "phone": "13800138000",
  "action": "login"
}
```

2. **验证码登录**：

```http
POST /user/verify-code-login
Content-Type: application/json

{
  "email": "user@example.com",
  "phone": "13800138000",
  "verifyCode": "123456"
}
```

### 5. 第三方登录

```http
POST /user/third-party-login
Content-Type: application/json

{
  "provider": "github",
  "code": "github_authorization_code",
  "state": "123456"
}
```

### 6. 登出

```http
POST /auth/logout
Content-Type: application/json

{
  "token": "access_token",
  "client_id": "test-client"
}
```

## SDK使用

### 1. 初始化SDK

```go
import "github.com/LandcLi/LandcSSO/pkg/sdk"

config := &sdk.Config{
    ClientID:     "test-client",
    ClientSecret: "test-secret",
    RedirectURI:  "http://localhost:3000/callback",
    Issuer:       "http://localhost:8080",
    Scope:        "openid profile email",
}

client := sdk.NewClient(config)
```

### 2. 获取授权URL

```go
state := "123456"
authURL := client.GetAuthorizationURL(state)
// 重定向用户到authURL
```

### 3. 交换令牌

```go
code := "authorization_code"
tokenResp, err := client.ExchangeToken(code)
if err != nil {
    // 处理错误
}

accessToken := tokenResp.AccessToken
refreshToken := tokenResp.RefreshToken
```

### 4. 获取用户信息

```go
userInfo, err := client.GetUserInfo(accessToken)
if err != nil {
    // 处理错误
}

fmt.Println("User ID:", userInfo.Sub)
fmt.Println("Username:", userInfo.PreferredUsername)
fmt.Println("Email:", userInfo.Email)
```

### 5. 刷新令牌

```go
newTokenResp, err := client.RefreshToken(refreshToken)
if err != nil {
    // 处理错误
}

newAccessToken := newTokenResp.AccessToken
```

### 6. 第三方登录

```go
req := &sdk.ThirdPartyLoginRequest{
    Provider: "github",
    Code:     "github_authorization_code",
    State:    "123456",
}

tokenResp, err := client.ThirdPartyLogin(req)
if err != nil {
    // 处理错误
}
```

### 7. 获取第三方授权链接

#### 7.1 获取微信授权链接

```go
redirectURI := "http://localhost:3000/wechat/callback"
state := "123456"

authURL, err := client.GetWechatAuthURL(redirectURI, state)
if err != nil {
    // 处理错误
}
// 重定向用户到authURL
```

#### 7.2 获取GitHub授权链接

```go
redirectURI := "http://localhost:3000/github/callback"
state := "123456"
scope := "user:email"
codeChallenge := "challenge123"
codeChallengeMethod := "S256"

authURL, err := client.GetGitHubAuthURL(redirectURI, state, scope, codeChallenge, codeChallengeMethod)
if err != nil {
    // 处理错误
}
// 重定向用户到authURL
```

#### 7.3 获取支付宝授权链接

```go
redirectURI := "http://localhost:3000/alipay/callback"
state := "123456"

authURL, err := client.GetAlipayAuthURL(redirectURI, state)
if err != nil {
    // 处理错误
}
// 重定向用户到authURL
```

#### 7.4 服务端回调端点（推荐）

第三方授权后由 **SSO 后端统一处理回调**（无需前端参与 code 交换）：

- 回调端点：`GET /auth/callback/:provider`（如 `/auth/callback/github`）
- GitHub 授权后 302 重定向到该端点（携带 `code` + `state`）
- SSO 服务端依次执行：**校验 state（防 CSRF）→ 用 code 换 token → 调 LUM 完成登录/注册**
- 成功后 302 重定向到 `frontend.callback_url`（配置项），token 通过 URL fragment 传递（不进入服务器日志）

**配置示例**（config.yaml）：

```yaml
frontend:
  # 回调成功后重定向的前端地址，前端从 URL fragment 中读取 token/refresh_token
  callback_url: "http://localhost:3000"

third_party:
  github:
    client_id: "<Client ID>"
    client_secret: "<Client Secret>"
    # 必须与 GitHub OAuth App 注册的 Authorization callback URL 的 scheme://host:port 完全一致
    redirect_uri: "http://localhost:18080/auth/callback/github"
```

> **state 说明**：state 由 SSO 服务端生成（`GET /auth/third-party-login` 返回 `data.state`），
> 回调时（`POST /auth/login` 或服务端回调端点）必须原样回传，校验通过后一次性销毁。

### 8. 生物识别登录（规划中）

> ⚠️ 该功能后端尚未实现（依赖 LandcUserManager），SDK 方法调用会返回"接口不存在"，请勿在生产接入。

```go
req := &sdk.BiometricLoginRequest{
    UserID:       "123456",
    BiometricID:  "fingerprint_1",
    Signature:    "biometric_signature",
    DeviceID:     "device_123",
    DeviceInfo:   "iPhone 13",
}

tokenResp, err := client.BiometricLogin(req)
if err != nil {
    // 处理错误
}
```

### 9. 扫码登录（规划中）

> ⚠️ 该功能后端尚未实现（依赖 LandcUserManager），SDK 方法调用会返回"接口不存在"，请勿在生产接入。

#### 9.1 开始扫码登录

```go
req := &sdk.ScanCodeLoginRequest{
    ClientID:    "test-client",
    RedirectURI: "http://localhost:3000/callback",
    Scope:       "openid profile email",
    State:       "123456",
}

qrcodeResp, err := client.StartScanCodeLogin(req)
if err != nil {
    // 处理错误
}

// 显示二维码给用户
fmt.Println("QR Code URL:", qrcodeResp.QRCodeURL)
fmt.Println("QR Code ID:", qrcodeResp.QRCodeID)
```

#### 8.2 检查扫码登录状态

```go
req := &sdk.ScanCodeStatusRequest{
    Code: qrcodeResp.QRCodeID,
}

statusResp, err := client.CheckScanCodeStatus(req)
if err != nil {
    // 处理错误
}

if statusResp.Status == "completed" && statusResp.TokenResponse != nil {
    // 登录成功，获取令牌
    accessToken := statusResp.TokenResponse.AccessToken
}
```

### 9. 审计日志

```go
req := &sdk.AuditLogRequest{
    UserID:    "123456",
    EventType: "login",
    StartTime: time.Now().Add(-24 * time.Hour),
    EndTime:   time.Now(),
    Page:      1,
    PageSize:  10,
}

logsResp, err := client.GetAuditLogs(req)
if err != nil {
    // 处理错误
}

// 处理审计日志
for _, log := range logsResp.Logs {
    fmt.Println("Event:", log.EventType, "at", log.Timestamp)
}
```

### 10. 监控

#### 10.1 获取系统状态

```go
systemStatus, err := client.GetSystemStatus()
if err != nil {
    // 处理错误
}

fmt.Println("CPU Usage:", systemStatus.CPUUsage)
fmt.Println("Memory Usage:", systemStatus.MemoryUsage)
```

#### 10.2 获取认证指标

```go
authMetrics, err := client.GetAuthMetrics()
if err != nil {
    // 处理错误
}

fmt.Println("Login Success Rate:", authMetrics.LoginSuccessRate)
fmt.Println("Average Login Latency:", authMetrics.AverageLoginLatency)
```

#### 10.3 获取异常事件

```go
exceptionEvents, err := client.GetExceptionEvents()
if err != nil {
    // 处理错误
}

for _, event := range exceptionEvents.Events {
    fmt.Println("Exception:", event.Type, "at", event.Timestamp)
}
```

## 配置说明

### 服务器配置

| 配置项 | 类型 | 默认值 | 描述 |
|-------|------|-------|------|
| server.port | int | 8080 | 服务端口 |
| server.host | string | "0.0.0.0" | 服务主机 |
| server.mode | string | "debug" | 运行模式（debug/release） |

### 数据库配置

| 配置项 | 类型 | 默认值 | 描述 |
|-------|------|-------|------|
| database.driver | string | "mysql" | 数据库驱动 |
| database.host | string | "localhost" | 数据库主机 |
| database.port | int | 3306 | 数据库端口 |
| database.user | string | "root" | 数据库用户名 |
| database.password | string | "root" | 数据库密码 |
| database.dbname | string | "sso" | 数据库名称 |
| database.charset | string | "utf8mb4" | 字符集 |
| database.parseTime | bool | true | 是否解析时间 |
| database.loc | string | "Local" | 时区 |

### Redis配置

| 配置项 | 类型 | 默认值 | 描述 |
|-------|------|-------|------|
| redis.host | string | "localhost" | Redis主机 |
| redis.port | int | 6379 | Redis端口 |
| redis.password | string | "" | Redis密码 |
| redis.db | int | 0 | Redis数据库 |
| redis.poolSize | int | 10 | 连接池大小 |

### JWT配置

| 配置项 | 类型 | 默认值 | 描述 |
|-------|------|-------|------|
| jwt.secret | string | "your-secret-key" | JWT密钥 |
| jwt.issuer | string | "sso-server" | JWT颁发者 |
| jwt.accessTokenExpiry | int | 1800 | 访问令牌过期时间（秒） |
| jwt.refreshTokenExpiry | int | 86400 | 刷新令牌过期时间（秒） |
| jwt.maxConcurrentSessions | int | 5 | 最大并发会话数 |
| jwt.signingMethod | string | "HS256" | 签名方法（HS256/RS256） |
| jwt.privateKeyPath | string | "" | RSA私钥路径（RS256时使用） |
| jwt.publicKeyPath | string | "" | RSA公钥路径（RS256时使用） |

### 日志配置

| 配置项 | 类型 | 默认值 | 描述 |
|-------|------|-------|------|
| log.provider | string | "console" | 日志提供者（console/zap/logrus/std） |
| log.level | string | "info" | 日志级别（debug/info/warn/error） |
| log.format | string | "text" | 日志格式（text/json） |
| log.outputPath | string | "stdout" | 日志输出路径 |

### 邮件配置

| 配置项 | 类型 | 默认值 | 描述 |
|-------|------|-------|------|
| mail.host | string | "" | SMTP服务器地址 |
| mail.port | int | 587 | SMTP服务器端口 |
| mail.username | string | "" | SMTP用户名 |
| mail.password | string | "" | SMTP密码 |
| mail.from | string | "" | 发件人邮箱 |
| mail.useSSL | bool | false | 是否使用SSL |

### 短信配置

| 配置项 | 类型 | 默认值 | 描述 |
|-------|------|-------|------|
| sms.provider | string | "" | 短信服务商（aliyun/tencent） |
| sms.apiKey | string | "" | API密钥 |
| sms.secretKey | string | "" | 密钥 |
| sms.signName | string | "" | 短信签名 |
| sms.templates | map[string]string | {} | 短信模板ID | |

## API文档

详细的API文档请查看 [docs/api.md](docs/api.md)。

## 设计文档

详细的设计文档请查看 [docs/design.md](docs/design.md)。

## 测试

运行测试：

```bash
go test ./tests/...
```

## 部署

### 1. 构建

```bash
go build -o sso-server cmd/api/main.go
```

### 2. 运行

```bash
./sso-server --config=config.yml
```

### 3. Docker部署

创建Dockerfile：

```dockerfile
FROM golang:1.24.0-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o sso-server cmd/api/main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/sso-server /app/
COPY --from=builder /app/config.yml /app/
EXPOSE 8080
CMD ["./sso-server", "--config=config.yml"]
```

构建和运行Docker容器：

```bash
docker build -t landc-sso .
docker run -d -p 8080:8080 --name landc-sso landc-sso
```

## 安全建议

1. **使用HTTPS**：在生产环境中，必须使用HTTPS传输
2. **设置强密码**：为JWT密钥、数据库密码等设置强密码
3. **限制访问**：限制管理接口的访问权限
4. **定期更新密钥**：定期更新RSA密钥对
5. **监控异常**：监控异常登录和令牌使用
6. **数据备份**：定期备份数据库和Redis数据

## 许可证

MIT License

## 联系方式

- 项目地址：https://github.com/LandC/LandcSSO
- 问题反馈：https://github.com/LandC/LandcSSO/issues
