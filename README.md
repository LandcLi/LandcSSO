# LandcSSO

LandcSSO是一个基于Go语言开发的单点登录（SSO）系统，支持OAuth 2.0和OpenID Connect协议，为企业应用提供统一的身份认证和授权服务。

## 功能特性

- **统一认证**：用户只需登录一次即可访问所有信任的应用
- **多协议支持**：实现了OAuth 2.0和OpenID Connect协议
- **多登录方式**：支持用户名/密码登录、短信/邮箱验证码登录、第三方登录（微信、钉钉、GitHub等）
- **无缝体验**：支持静默登录、记住登录状态、设备信任机制
- **安全可靠**：使用JWT令牌、RSA签名、HTTPS传输等安全措施
- **会话管理**：支持并发会话数限制，超过限制时自动撤销最旧的会话
- **完整登出**：支持完整的登出流程，包括通知所有已登录应用
- **高性能**：基于Go语言和Redis实现，支持高并发
- **可扩展**：模块化设计，易于扩展和集成
- **完整的SDK**：提供服务提供方（SP）SDK，方便应用集成
- **详细的文档**：完善的设计文档和API文档
- **全面的测试**：实现了单元测试、集成测试、性能测试和安全测试

## 技术栈

- **后端**：Go 1.24.0 + Gin框架
- **数据存储**：MySQL + Redis
- **认证协议**：OAuth 2.0 + OpenID Connect
- **安全**：JWT + RSA + HTTPS
- **日志**：LandcLogFace
- **API响应**：LandcCommonApi

## 目录结构

```
LandcSSO/
├── cmd/              # 命令行入口
│   └── api/          # API服务入口
├── internal/         # 内部包
│   ├── api/          # API路由和控制器
│   ├── service/      # 业务逻辑
│   ├── model/        # 数据模型
│   ├── repository/   # 数据访问
│   ├── middleware/   # 中间件
├── pkg/              # 公共包
│   ├── sdk/          # 服务提供方SDK
│   ├── config/       # 配置管理
│   └── logger/       # 日志管理
├── tests/            # 测试文件
├── docs/             # 文档
├── sqls/             # SQL脚本
├── steps/            # 步骤记录
├── config.yml        # 配置文件
├── go.mod            # 依赖管理
└── README.md         # 项目说明
```

## 快速开始

### 1. 环境准备

- Go 1.24.0或更高版本
- MySQL 5.7或更高版本
- Redis 5.0或更高版本

### 2. 安装依赖

```bash
go mod tidy
```

### 3. 数据库初始化

执行SQL脚本初始化数据库：

```bash
mysql -u root -p < sqls/init.sql
```

### 4. 配置文件

修改`config.yml`文件，配置数据库、Redis等参数：

```yaml
server:
  port: 8080
  host: "0.0.0.0"
  mode: "debug"

database:
  driver: "mysql"
  host: "localhost"
  port: 3306
  user: "root"
  password: "root"
  dbname: "sso"
  charset: "utf8mb4"
  parseTime: true
  loc: "Local"

redis:
  host: "localhost"
  port: 6379
  password: ""
  db: 0
  poolSize: 10

jwt:
  secret: "your-secret-key"
  issuer: "sso-server"
  accessTokenExpiry: 1800  # 30分钟
  refreshTokenExpiry: 86400  # 24小时
  maxConcurrentSessions: 5  # 最大并发会话数
  signingMethod: "HS256"  # 签名方法（HS256/RS256）
  privateKeyPath: ""  # RSA私钥路径（RS256时使用）
  publicKeyPath: ""  # RSA公钥路径（RS256时使用）

log:
  provider: "console"
  level: "info"
  format: "text"
  outputPath: "stdout"
```

### 5. 启动服务

```bash
go run cmd/api/main.go
```

服务将在 `http://localhost:8080` 启动。

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
import "LandcSSO/pkg/sdk"

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
