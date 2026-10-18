# 开发、测试与Windows构建

在Windows x64普通用户终端使用Python3.12+和uv：

```powershell
uv sync --locked --python 3.12 --group build
.\.venv\Scripts\python.exe -m pytest -q --tb=short tests 软件检测/tests
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe scripts/build_windows.py
```

若默认TEMP或缓存不可写，仅对当前终端设置：

```powershell
New-Item -ItemType Directory -Force -Path .cache/tmp | Out-Null
$env:TEMP = (Resolve-Path .cache/tmp).Path
$env:TMP = $env:TEMP
$env:PYTHONUTF8 = '1'
uv sync --locked --group build --cache-dir .cache/uv --link-mode copy
```

所有正常测试使用虚构网络、内存凭据、临时文件和本机HTTP/TLS模拟服务器，不访问校园账号或正式任务。Qt单实例/管道断言需普通Windows用户能力；受限会话拒绝时保留断言、单独记录环境。线程异常和未处理对象警告视为失败。

## 冻结检查

`CampusAutoConnect-CLI.exe --self-check <模式>`支持runtime、network、gui、background、credentials、startup、startup-ui和browser。逐项检查退出码和JSON的passed；credentials使用独立随机WinVault命名空间和虚构值，startup使用随机任务且禁用触发，均需最终清理；browser仅连接本机模拟Portal。

另检查GUI EXE本体、真实Windows托盘、中文/空格路径独立副本，并移除开发Python搜索路径。所有这些检查均不替代真实校园网、重启、睡眠和跨区域验收。

## 构建产物核对

输出限定build/dist，完整保留目录。若旧输出含reports、日志、真实配置或抓包，先在本人私密位置妥善保管，改用干净构建目录；脚本拒绝将它们纳入分发，不自动删除本人数据。

核对BUILD_INFO源码提交/dirty标记、组件版本/许可、EXE x64资源、SHA256SUMS逐文件、ZIP CRC及旁附SHA-256。源码归档与WindowsZIP均无运行配置；全新用户目录应为空档案、自动认证关闭且无登录任务。

隐私扫描对固定公开清单进行，不把开发者原Git、报告或抓包一起推送。Git提交使用GitHub隐私邮箱；不在命令行、文件或日志中填写访问令牌。

历史建设、失败与未验证范围见[项目历史](PROJECT_HISTORY.md)，使用与配置见[配置指南](release/CONFIGURATION.md)。
