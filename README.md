<p align="center"><img src="src/campus_autoconnect/assets/app.png" width="144" alt="Campus AutoConnect 图标"></p>

# Campus AutoConnect · 校园网连接助手

面向 **Windows 10/11 x64** 的校园网自动认证工具。Windows 建立连接后，软件按对应网络档案检测联网情况，必要时认证。当前源码支持北工大 Wi-Fi ePortal，以及有线 HTTPS 的 Dr.COM 和 ePortal 分支。

## 最新公开版 · v1.3.3

[下载 Windows 安装程序](https://github.com/astraelia/CampusAutoConnect/releases/download/v1.3.3/CampusAutoConnect-1.3.3-setup-win-x64.exe) · [下载便携 ZIP](https://github.com/astraelia/CampusAutoConnect/releases/download/v1.3.3/CampusAutoConnect-1.3.3-win-x64.zip) · [发布详情和校验值](https://github.com/astraelia/CampusAutoConnect/releases/tag/v1.3.3) · [历史版本](https://github.com/astraelia/CampusAutoConnect/releases)

v1.3.3 修复有线切网后的自动认证恢复及托盘图标注册问题，优化有线门户预检与登录后的联网复核。打开软件时默认启动或复用后台，自动认证仍由全局和档案两级许可控制。

- **Windows 安装向导**提供文件夹浏览、安装位置选择和可选桌面快捷方式。安装后可从开始菜单启动，也可在 Windows「已安装的应用」中卸载。
- **有线和 Wi-Fi 自动选择**。物理网线接通且 IPv4 和网关就绪时优先处理有线。北工大有线自动认证支持已核对的 HTTPS Dr.COM 和 ePortal 流程。
- **Wi-Fi 抓包回填**。在档案编辑时用专用浏览器手动登录一次，即可保存脱敏抓包并回填认证地址。关闭专用浏览器也会保存已记录内容。
- **配置检查和全面诊断**。保存档案时立即检查认证准备情况。全面诊断涵盖选网、档案、路由、TLS、实时协议、凭据后端和后台。
- **本机凭据查看**。已保存的账号和密码默认以星号显示。按住「显示」查看，点击「隐藏」恢复遮罩。

[安装和升级说明](docs/release/INSTALL_UNINSTALL.md) · [首次配置](docs/release/CONFIGURATION.md) · [完整手册](docs/release/USER_MANUAL.md) · [常见问题](docs/release/FAQ.md) · [完整版本记录](docs/release/CHANGELOG.md)

## 适用范围与实测状态

- **有线校园网**。本版自动认证仅适配北京工业大学已核验的有线门户流程。其他校区或学校的有线网络是否兼容，需现场验证。北工大有线手动认证已有现场记录，v1.3.3 的有线自动认证全流程和实际插拔切换仍待现场验收。
- **无线 Wi-Fi**。已适配北京工业大学本部使用已核验 ePortal 流程的校园 Wi-Fi，并有自动认证的现场记录。通州校区及其他学校尚未实测，可以通过配置界面的抓包功能辅助识别认证入口。若当地门户与软件已支持的认证流程兼容，并通过实时校验，完成档案配置后才可使用自动认证。

有线网卡接通且取得 IPv4 地址和网关时优先检查有线。拔线或有线未就绪时检查 Windows 当前连接的 Wi-Fi。应用使用 Windows 的路由和已关联的 Wi-Fi。

## 下载后是什么状态

每台电脑的有线和 Wi-Fi 档案由使用者配置，账号密码保存在 Windows 安全存储中。

| 项目 | 新电脑 / 新 Windows 用户的初始状态 |
| --- | --- |
| 网络档案 | 空，`config/config.example.json` 只有空的 `profiles` 列表 |
| 校园账号密码 | 由本人保存至本机 Windows Credential Manager |
| 后台监测 | 打开应用时默认启动或复用 |
| 全局自动认证 | 关闭 |
| 档案自动认证、HTTP、全零 MAC 兼容许可 | 不预授予；由本人按精确档案确认 |
| Windows 登录自启动 | 未安装；需本人主动开启 |
| 本机记录 | 不从仓库导入，不随 GitHub 下载迁移 |

**在同一 Windows 用户下重新下载或升级时，软件会继续使用该用户原有的本地设置与安全凭据。** 这属于本机存储复用；下载包没有携带这些数据。新用户须按下方流程重新配置。

## 五步开始使用

1. 运行安装程序，点击「浏览」选择可写的安装目录，按需勾选桌面快捷方式。使用便携版时，将 ZIP 完整解压并保留 `_internal`。
2. 接上校园网线或通过 Windows 连接校园 Wi-Fi，打开「校园网连接助手」，点击「配置当前网络…」。
3. 有线填写学校的 HTTPS 登录网址。Wi-Fi 可点“现场抓包并回填”，在专用浏览器手动登录后停止保存。核对配置并点击“保存并检查”。[配置指南](docs/release/CONFIGURATION.md)
4. 在“安全凭据”输入自己的账号密码，保存并等待“已保存并复核”。当前确实待认证时，点击一次“手动测试认证”；原本已联网时会跳过登录。
5. 手动连接成功后，再开启对应档案的自动认证和全局自动认证。需要 Windows 登录时运行软件，可在“后台与启动”开启“登录 Windows 后自动启动到托盘”。

账号密码只存于本机 Windows 安全凭据。录入新区用于更新凭据，已保存的内容在同页的星号区域查看。具体步骤见[快速开始](docs/release/QUICK_START.md)和[使用手册](docs/release/USER_MANUAL.md)。

## 功能与入口

| 功能 / 页面 | 作用 | 使用帮助 |
| --- | --- | --- |
| 连接概览 | 检测互联网、查看认证阶段、手动认证、取消操作 | [检测与手动认证](docs/release/FEATURES.md#overview) |
| 网络档案 | 有线网卡和网关、精确 SSID、Wi-Fi 抓包回填、档案导入导出 | [档案管理](docs/release/FEATURES.md#profiles) · [抓包回填](docs/release/FEATURES.md#capture) |
| 安全凭据 | 安全保存/更新/删除、写后核对、历史与当前状态 | [凭据管理](docs/release/FEATURES.md#credentials) |
| 后台与启动 | 自动认证、后台启停、当前用户登录托盘启动、旧路径修复 | [自动认证与启动](docs/release/FEATURES.md#automation) |
| 诊断与监测 | 全面检查网卡、联网、档案、路由、TLS、实时协议和后台 | [诊断与监测](docs/release/FEATURES.md#logs) |
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

测试和 Windows 构建：

```powershell
uv sync --locked --python 3.12 --group build
.\.venv\Scripts\python.exe -m pytest -q tests 软件检测/tests
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe scripts/build_windows.py
```

如需同时生成安装程序，给构建命令加 `--iscc "<Inno Setup 的 ISCC.exe 路径>"`。两种构建产物和 SHA-256 校验文件都在 `dist/`。构建目录必须没有配置、日志、抓包或运行报告。[Inno Setup](https://jrsoftware.org/inno-setup/downloads) · [开发与验证说明](docs/testing.md)

```text
src/campus_autoconnect/  当前核心逻辑、Windows适配、GUI/CLI及内置帮助
tests/                  虚构网络、本地HTTP/TLS模拟服务器和GUI回归
config/                 默认空配置示例
scripts/ packaging/     启动、检查、公开导出和Windows构建
docs/release/           安装、配置、每项功能、隐私及排错教程
软件检测/               复用主程序规则的兼容检测器源码和测试
```

## 开发记录与反馈

[项目历史与已知问题](docs/PROJECT_HISTORY.md)记录从 M1 到当前版的主要建设、失败和修复。公开仓库使用经过隐私审查的源码快照。

提交问题前先读[常见问题](docs/release/FAQ.md)，使用[反馈模板](docs/release/FEEDBACK_TEMPLATE.md)，仅提供版本、步骤、错误码和经过检查的脱敏诊断。请勿上传账号密码、真实配置、SSID/IP/认证主机、Cookie、Token、完整 HAR 或凭据截图。

代码测试、打包程序检查、真实网络测试和最终阶段验收分别记录。Campus AutoConnect 是独立开发项目。

许可证遵循仓库已有的 [GNU GPL v3.0](LICENSE)。Python、Qt/PySide6、Playwright 等第三方组件遵循各自许可证，Windows 包附带相关许可文本。
