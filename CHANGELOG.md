# Changelog

本项目所有重要变更均记录在此文件中。格式基于
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

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
