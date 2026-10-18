"""Standalone entry. Source mode imports the existing project without modifying it."""

import argparse
import json
import os
import sys
import threading
from contextlib import ExitStack
from pathlib import Path

sys.dont_write_bytecode = True
if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def main() -> int:
    parser = argparse.ArgumentParser(description="校园网软件检测，不读取凭据或发送登录")
    parser.add_argument("--check", action="store_true", help="无窗口分步复查并保存脱敏报告")
    parser.add_argument("--target", type=Path, help="选定 CampusAutoConnect.exe")
    parser.add_argument("--self-check", action="store_true", help="离线合成场景自检")
    parser.add_argument("--gui-self-check", action="store_true", help="隔离窗口及异步自检")
    parser.add_argument("--preview", type=Path, help="只渲染虚构数据预览")
    args = parser.parse_args()
    with ExitStack() as streams:
        for name in ("stdout", "stderr"):
            if getattr(sys, name) is None:
                setattr(sys, name, streams.enter_context(open(os.devnull, "w", encoding="utf-8")))
        try:
            if args.self_check:
                from campus_inspector.selfcheck import offline_check

                result = offline_check()
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["passed"] else 1
            if args.gui_self_check:
                from campus_inspector.selfcheck import gui_check

                result = gui_check()
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["passed"] else 1
            if args.preview:
                os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
                from campus_inspector.gui import preview

                preview(args.preview)
                return 0
            if args.check:
                from campus_inspector.session import Session

                from campus_autoconnect.infrastructure.config import user_data_dir

                session = Session(user_data_dir(), lambda _: None)
                result = session.execute(args.target, threading.Event(), monitor=False)
                print(json.dumps(result.payload(), ensure_ascii=False, indent=2))
                return 1 if any(s.outcome.value in {"失败", "阻塞"} for s in result.steps) else 0
            from campus_inspector.gui import main as gui

            return gui()
        except Exception as exc:
            # Exception text and traceback may contain network identifiers or local paths.
            print(
                json.dumps(
                    {
                        "passed": False,
                        "code": "inspector_failure",
                        "exception_type": type(exc).__name__,
                    },
                    ensure_ascii=True,
                )
            )
            if os.name == "nt" and not any(
                (args.check, args.self_check, args.gui_self_check, args.preview)
            ):
                import ctypes

                ctypes.windll.user32.MessageBoxW(
                    None,
                    "检测工具启动失败，请保留完整解压目录并运行 CLI 自检。",
                    "校园网软件检测",
                    0x10,
                )
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
