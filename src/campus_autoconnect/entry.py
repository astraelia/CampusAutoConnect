"""Shared entry for frozen GUI, console and isolated, non-authenticating self checks."""

import os
import sys
from contextlib import ExitStack


def main() -> int:
    # A windowed frozen executable has no console streams. Libraries may still write to them.
    with ExitStack() as streams:
        for name in ("stdout", "stderr"):
            if getattr(sys, name) is None:
                setattr(sys, name, streams.enter_context(open(os.devnull, "w", encoding="utf-8")))
        try:
            return _dispatch(sys.argv[1:])
        except Exception as exc:
            message = f"启动失败（{type(exc).__name__}），请检查完整解压目录并运行 CLI 隔离自检。"
            if (
                os.name == "nt"
                and sys.argv[1:] in ([], ["--startup"])
                and "-cli" not in os.path.basename(sys.executable).lower()
            ):
                import ctypes

                ctypes.windll.user32.MessageBoxW(None, message, "Campus AutoConnect", 0x10)
            else:
                print(message, file=sys.stderr)
            return 1


def _dispatch(arguments: list[str]) -> int:
    if arguments == ["--startup"]:
        from campus_autoconnect.ui.app import main as gui

        return gui(startup=True)
    if arguments[:1] == ["--support-watch"]:
        from campus_autoconnect.infrastructure.lifecycle import watch

        return watch(arguments[1:])
    if arguments[:1] == ["--self-check"]:
        from campus_autoconnect.selfcheck import main as selfcheck

        return selfcheck(arguments[1:])
    if arguments[:1] == ["--background"]:
        from campus_autoconnect.cli.main import main as cli

        return cli(["monitor", "run", *arguments[1:]])
    if (
        arguments[:1] == ["--cli"]
        or os.path.basename(sys.executable).lower() == "campusautoconnect-cli.exe"
    ):
        from campus_autoconnect.cli.main import main as cli

        return cli(arguments[1:] if arguments[:1] == ["--cli"] else arguments)
    if arguments:
        # Unknown GUI arguments must not silently start a window or monitoring.
        return 2
    from campus_autoconnect.ui.app import main as gui

    return gui()


if __name__ == "__main__":
    raise SystemExit(main())
