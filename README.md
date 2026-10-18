<p align="center"><img src="src/campus_autoconnect/assets/app.png" width="144" alt="Campus AutoConnect 图标"></p>

# Campus AutoConnect · 校园 Wi-Fi 连接助手

面向 **Windows 10/11 x64** 的校园网自动认证工具，首个适配对象为**北京工业大学（BJUT）**。连接校园 Wi-Fi 后，可检测互联网状态，按本人配置的精确网络档案完成认证，并在 Windows 登录后通过托盘持续运行。

**当前版本：1.0.1** · Python 3.12+ · PySide6 · 本地运行 · GPL-3.0

[下载 Windows 版](https://github.com/astraelia/CampusAutoConnect/releases/latest) · [首次配置](docs/release/CONFIGURATION.md) · [完整手册](docs/release/USER_MANUAL.md) · [各功能说明](docs/release/FEATURES.md) · [常见问题](docs/release/FAQ.md) · [隐私与默认配置](docs/release/PRIVACY.md)

## 适用范围与实测状态

**理论适用范围：** 在分别完成对应网络的精确 SSID、可信认证入口、安全凭据及自动认证许可配置，且该网络使用本项目已适配的 BJUT ePortal 认证流程时，设计上可用于北京工业大学本部各区域的校园网自动认证。

**已实测：** 北京工业大学**中蓝公寓宿舍内校园网**能够自动连接。

**待验证：** 本部校区其他区域及其他校区尚待实测，暂不承诺所有区域均可直接使用。不同 SSID、入口、路由或认证分支需要分别配置和验证；1.0.1 完整开机连接耗时及其他电脑兼容性也需单独测试。

这里的“自动连接”指 **Windows 已连接校园 Wi-Fi 后，由本软件完成校园网认证**。软件不负责搜索、选择或切换 Wi-Fi，也不绕过验证码、设备限制或学校账号权限。

## 下载后是什么状态

仓库和发布包均不附带作者的账号密码、校园 SSID、IP、网关、认证主机、运行配置、日志或抓包。

| 项目 | 新电脑 / 新 Windows 用户的初始状态 |
| --- | --- |
| 网络档案 | 空；`config/config.example.json` 只有空的 `profiles` 列表 |
| 校园账号密码 | 无；需要本人保存至当地 Windows Credential Manager |
| 全局自动认证 | 关闭 |
| 档案自动认证、HTTP、全零 MAC 兼容许可 | 不预授予；由本人按精确档案确认 |
| Windows 登录自启动 | 未安装；需本人主动开启 |
| 本机记录 | 不从仓库导入，不随 GitHub 下载迁移 |

**在同一 Windows 用户下重新下载或升级时，软件会继续使用该用户原有的本地设置与安全凭据。** 这属于本机存储复用；下载包没有携带这些数据。新用户须按下方流程重新配置。

## 五步开始使用

1. 从 [Releases](https://github.com/astraelia/CampusAutoConnect/releases) 下载 `CampusAutoConnect-1.0.1-win-x64.zip`，完整解压到本人可写的固定目录。保留 EXE、`_internal` 和文档的相对位置。无需安装 Python；网页抓包需本机已有 Edge 或 Chrome。
2. 先通过 Windows 连接自己的校园 Wi-Fi，运行 `CampusAutoConnect.exe`。点击“检测网络”，再点击“配置当前网络…”，或到“网络档案”添加档案。
3. 填写本人核对的精确 SSID、认证页和认证服务地址。只在实际需要时明确允许 HTTP 或页面全零 MAC 兼容。**不要照抄他人的网络参数。** 详细字段见[配置指南](docs/release/CONFIGURATION.md)。
4. 在“安全凭据”输入自己的账号密码，保存并等待“已保存并复核”。当前确实待认证时，点击一次“手动测试认证”；原本已联网时会跳过登录。
5. 手动连接成功后，再打开对应档案的自动认证、全局自动认证并启动后台。需要开机使用时，在“后台与启动”主动开启“登录 Windows 后自动启动到托盘”。

账号密码只存于本机 Windows 安全凭据。软件不会回填已保存的密码；重开后输入框为空属于正常行为。具体步骤见[快速开始](docs/release/QUICK_START.md)和[使用手册](docs/release/USER_MANUAL.md)。

## 功能与入口

| 功能 / 页面 | 作用 | 使用帮助 |
| --- | --- | --- |
| 连接概览 | 检测互联网、查看认证阶段、手动认证、取消操作 | [检测与手动认证](docs/release/FEATURES.md#overview) |
| 网络档案 | 多 SSID、精确匹配、独立许可、导入导出 | [档案管理](docs/release/FEATURES.md#profiles) |
| 安全凭据 | 安全保存/更新/删除、写后核对、历史与当前状态 | [凭据管理](docs/release/FEATURES.md#credentials) |
| 后台与启动 | 自动认证、后台启停、当前用户登录托盘启动、旧路径修复 | [自动认证与启动](docs/release/FEATURES.md#automation) |
| 诊断与监测 | 脱敏事件、实际记录、独立复查、无凭据深入诊断 | [诊断与监测](docs/release/FEATURES.md#logs) |
| 抓包与分析 | 专用 Edge/Chrome 网页对照、结构分析、报告保存 | [浏览器抓包](docs/release/FEATURES.md#capture) |
| 外观设置 | 系统/浅/深主题、关闭到托盘、报告保留与清理 | [外观与报告管理](docs/release/FEATURES.md#settings) |
| 使用帮助 | 12 章离线教程、关键词搜索、操作页跳转 | [帮助页面](docs/release/FEATURES.md#help) |
| 托盘与完整退出 | 后台常驻、恢复窗口、异步操作、协作退出 | [托盘与退出](docs/release/FEATURES.md#tray) |
| CLI | 高级查询、诊断和隔离自检，与 GUI 共用服务 | [命令行](docs/release/FEATURES.md#cli) |

自动认证同时要求：精确档案启用且允许自动认证、全局允许、后台运行、实时网络与认证门槛通过。明确临时故障最多尝试三次；凭据、协议、TLS、信任等故障停止自动尝试，防止无限登录。

## 隐私与安全

- 账号密码只交由显式 `WinVaultKeyring` 保存；不可用时停止，不回退到明文文件。
- 不读取未知、停用或歧义 SSID 对应的凭据；发现网页或导入配置不自动授予信任。
- HTTPS 证书验证保持开启。HTTP 兼容必须按档案明确许可；**HTTP 传输本身不加密账号密码**，不会自动从 HTTPS 降级。
- 读凭据前和提交前复核网络、精确目标、路由、取消和授权；不通过跳过 VPN/TUN 风险检查强行登录。
- 应用没有云端账户、遥测或自动上传功能。运行配置/日志在 `%LOCALAPPDATA%\CampusAutoConnect`；报告在程序目录的 `reports`。
- 配置导出和浏览器抓包可能包含网络名称、目标主机等私密网络信息，需私下保管，不要作为公开 Issue 附件。

完整说明见[隐私与默认配置](docs/release/PRIVACY.md)和[安全设计](docs/security.md)。

## 从源码运行与构建

在 Windows x64 的 PowerShell 中：

```powershell
git clone https://github.com/astraelia/CampusAutoConnect.git
cd CampusAutoConnect
uv sync --locked --python 3.12
.\.venv\Scripts\python.exe -m campus_autoconnect
```

测试和 Windows 目录包构建：

```powershell
uv sync --locked --python 3.12 --group build
.\.venv\Scripts\python.exe -m pytest -q tests 软件检测/tests
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe scripts/build_windows.py
```

输出位于 `dist/`。构建目录必须没有配置、日志、抓包或运行报告；发现这些内容会拒绝生成分发包。[开发与验证说明](docs/testing.md)包含隔离检查、临时目录和打包校验方法。

```text
src/campus_autoconnect/  当前核心逻辑、Windows适配、GUI/CLI及内置帮助
tests/                  虚构网络、本地HTTP/TLS模拟服务器和GUI回归
config/                 默认空配置示例
scripts/ packaging/     启动、检查、公开导出和Windows构建
docs/release/           安装、配置、每项功能、隐私及排错教程
软件检测/               复用主程序规则的兼容检测器源码和测试
```

## 开发记录与反馈

[项目历史与已知问题](docs/PROJECT_HISTORY.md)记录从 M1 到 1.0.1 的主要建设、失败和修复；[版本记录](docs/release/CHANGELOG.md)列出版本变化。公开仓库使用经过隐私审查的源码快照，不包含开发者的本机运行报告和私人审计资料。

提交问题前先读[常见问题](docs/release/FAQ.md)，使用[反馈模板](docs/release/FEEDBACK_TEMPLATE.md)，仅提供版本、步骤、错误码和经过检查的脱敏诊断。请勿上传账号密码、真实配置、SSID/IP/认证主机、Cookie、Token、完整 HAR 或凭据截图。

代码测试、冻结程序检查、真实网络测试和最终阶段验收分开记录。中蓝公寓的成功不代表其他校区或所有场景均已验收；软件为非校方项目。

许可证遵循仓库已有的 [GNU GPL v3.0](LICENSE)。Python、Qt/PySide6、Playwright 等第三方组件遵循各自许可证，Windows 包附带相关许可文本。
