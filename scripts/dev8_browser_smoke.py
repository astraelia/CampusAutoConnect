"""Development entry for the packaged local-browser self-check."""

import json

from campus_autoconnect.selfcheck_browser import run

if __name__ == "__main__":
    try:
        result = run()
    except Exception as exc:
        result = {"passed": False, "failure_type": type(exc).__name__}
    print(json.dumps(result, ensure_ascii=True, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
