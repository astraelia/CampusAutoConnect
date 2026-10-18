# Campus AutoConnect development rules

Windows 10/11 x64, Python 3.12+. Keep GUI/CLI on shared services.
Use exact SSID and endpoint permission, TLS verification, Windows WinVault only, single manual submission and bounded retries. Never commit real credentials, network profiles, logs, reports or captures. Default profiles must be empty and automatic authentication disabled.

Read README.md, docs/architecture.md, docs/security.md and docs/testing.md. Run full pytest, ruff check and ruff format --check before delivery. Mock success does not imply field acceptance.
