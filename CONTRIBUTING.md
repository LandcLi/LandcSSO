# Contributing to LandcSSO

感谢您考虑为 LandcSSO 贡献力量！

## 开发流程

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m 'feat: add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 提交 Pull Request

## 代码规范

- 遵循 [Go 官方代码规范](https://go.dev/doc/effective_go)
- 所有公共函数和类型必须有注释
- 运行时错误必须被处理或明确忽略
- 提交信息使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式

## 测试

- 新增代码应附带单元测试
- 运行 `make test` 确保所有测试通过
- 运行 `make lint` 确保代码风格一致

## 报告问题

请使用 GitHub Issues 报告 bug 或提出功能建议，并提供：
- 问题的清晰描述
- 复现步骤
- 期望行为与实际行为
- 环境信息（Go 版本、操作系统等）
