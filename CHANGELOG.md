# Changelog

本项目所有重要变更均记录在此文件中。格式基于
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

## [0.2.3] - 2026-10-26

### 新增

- **过期令牌/授权码的后台物理清理**。`tokens` 与 `authorization_codes` 两张表
  此前只有写入、从不清理：每次 login / refresh / 授权码签发都 INSERT 一条，
  长期运行会无限增长。现在 `serverlib.RegisterToRouter` 装配时启动一个后台
  定时任务（受 `token_cleanup.enabled` 控制，默认开启，默认每 1 小时一次），
  物理删除「refresh 已过期」或「已撤销」的令牌，以及过期授权码。
  - 关键语义：只按 `refresh_expires_at` 判断过期，不用 `expires_at` ——
    access 过期但 refresh 未过期时用户仍可刷新，提前删会断裂 refresh 链。
  - `tokenDao.DeleteExpiredTokens(now)` 返回删除条数，供运维/日志观测。
  - 单独失败只记日志，不中断后台任务。

## [0.2.2] - 2026-10-25

### 新增

- **`GET /.well-known/openid-configuration`（OIDC Discovery）**。
  README 早就写着这个地址能用，代码里根本没有这条路由 —— 标准 OIDC 客户端
  （Grafana / GitLab / ArgoCD / Keycloak 联邦）接入的第一步就是拉它，404 即失败。
  现在如实声明 issuer、authorization/token/userinfo/jwks/introspect/revocation
  各端点与支持的 scope、grant_type。
- **`GET /auth/jwks`（jwks_uri）**。`GetJWKS` 服务方法一直存在、公钥也一直在生成，
  但同样没有注册路由，等于验证签名的一侧永远拿不到公钥。现可匿名访问。
- **`GET /auth/userinfo`**。docs/api.md 里写了接口，实现缺失。现在按令牌里的
  用户取档案，返回标准扁平 JSON：`sub`（十进制 userID）、`preferred_username`、
  `name`、`email`、`phone_number`、`picture`。
  账号字段来自 LandcUserManager（本地进程内或远端 HTTP，取决于 `user_manager.mode`），
  SSO 不重复存一份用户档案。

### 说明

- 三个端点都返回**扁平 JSON**，不走 `{code,message,data}` 统一信封 ——
  标准客户端按 OIDC 规范解析，多套一层就解析失败。回归测试里显式断言了这一点。
- Discovery 与 JWKS 加入免鉴权白名单：客户端在拿到任何凭据之前就要拉它们。
- **能力边界已写入 README**：本服务签发 access_token / refresh_token，
  **不签发 id_token**，属于「OAuth2 授权服务器 + OIDC 的 userinfo/jwks 子集」。
  Discovery 的 `response_types_supported` 只有 `code`，不夸大能力。

### 依赖

- `LandcUserManager` 升级到 `v0.1.5`（`GetUserInfo` 支持按 user_id 查询，
  userinfo 需要按令牌主体反查档案）。

## [0.2.1] - 2026-10-25

### 变更

- 依赖升级到 `landc-go/frame v0.8.6`（`api v0.5.1`、`tools v0.7.1`）与
  `LandcUserManager v0.1.3`。框架侧修复了两处会让问题「看不见」的缺陷：
  - **HTTP 状态码被日志中间件吞成 200**：`/auth/*` 的参数校验失败、令牌无效
    在网关、APM、按状态码分支的客户端眼里全都是「成功」，只有 body 里的
    `code` 是错的。
  - **`other:` 段配置从未生效**：`other.*` 下的自定义配置解析后多套了一层，
    `GetOther` 恒取空。
- CI 改为在同一 job 内先 `CGO_ENABLED=0 go test`（对齐静态产物），
  再 `CGO_ENABLED=1 go test -race`（race 检测依赖 cgo）。

本版本无业务代码变更。

## [0.2.0] - 2026-10-25

### 新增

- **SQLite 开箱即用**：`database.driver: sqlite` + `auto_migrate: true` 即可零外部依赖启动，
  首次运行自动建库建表。框架侧已切换为纯 Go 驱动（`github.com/glebarez/sqlite`），
  不再依赖 CGO / gcc。
- **`serverlib` 库模式入口**：`RegisterToRouter / EnsureSchema / Seed / Models`。
  独立部署入口 `internal/cmd` 与「被其他服务嵌入」共用同一套装配逻辑，
  避免两种部署形态行为漂移。
- **用户中心接入方式可配置**（`user_manager.mode`）：
  - `local`（默认）：进程内复用 LandcUserManager，单二进制部署，无 HTTP 跳转；
  - `remote`：调用独立部署的 LUM。
  此前该地址硬编码为 `http://localhost:18081`，无法部署到其他环境。
- **种子客户端**（`seed.*`）：首次启动自动创建示例 OAuth 客户端，
  使新环境可立刻走通授权码 / 客户端凭证流程；生产环境应关闭并改用管理接口。
- **`tests/sqlite` 端到端冒烟**：临时目录真实 SQLite，覆盖建表、种子幂等性、
  客户端密钥哈希校验、`/auth/token`（客户端凭证）成功与错误密钥拒绝、
  以及进程内用户中心注册落库。
- `CHANGELOG.md`、`.gitignore` 补充运行期产物（`data/`、`bin/`、`*.db*`、`keys/`）。

### 修复

- **`log` 段配置类型冲突导致配置加载失败**：SSO 自有的 `Config.Log` 使用 int 枚举级别，
  而框架使用字符串级别，同一份 `config.yaml` 被两者重复解析时必然有一方失败
  （框架失败时会静默回退默认配置，连带丢失数据库配置）。现移除 SSO 的重复定义，
  统一由框架解析。
- **服务实现于包 `init()` 读取配置并 panic**：`NewAuthServiceImpl` 在构造期调用
  `config.GetConfig()`，配置未就绪时 `panic("failed to load config")`。
  任何提前 import 本包的宿主（如库模式装配、测试）都会连带崩溃。
  现改为调用期惰性获取，缺失时返回零值配置。
- **密钥服务在 import 期生成并写入 RSA 密钥文件**：`NewKeyServiceImpl` 在构造期加载/生成
  并落盘密钥，属「import 即产生磁盘副作用」的库反模式。现改为首次使用时惰性初始化
  （`sync.Once`），并为密钥表补上读写锁（此前并发访问 `keys` map 存在数据竞争）。
- **`serverlib` 未触发实现注册链**：仅 import `serverlib` 时 DAO/Service 实现未注册，
  `GetClientDao()` 返回 nil 导致空指针。现由 `serverlib` 自带注册链。
- `api.RegisterDefaultRoutes` 返回 error 而非 `panic`，路由注册失败可在启动阶段明确报错。
- 清理历史遗留的 `bin/`、`data/` 产物。

### 变更

- 依赖升级到 `landc-go/frame v0.8.5`。该版本修复了两个会让服务
  「看起来在跑、实际不可用」的框架缺陷：配置文件省略字段退化为零值
  （导致 `health_check.enabled`、`use_default_routes` 被静默关闭），
  以及 JWT 鉴权中间件拦截健康检查端点。
  升级后 `/health` 与 `/ready` 无需 Token 即可访问，编排系统探针可用。
