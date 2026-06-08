"""Launch the Agentic Security Platform UI.

Usage:
    python -m webapp
    python -m webapp --port 9000

Note: the default port is 9000 — deliberately NOT 8080. The full-loop security
demo deploys its target service on 8080 and, before each (re)deploy, kills any
process listening on that port. Running the UI on 8080 would make the demo kill
the UI itself. Keep the UI off 8080.
"""
from __future__ import annotations

import argparse
import logging
import sys
import webbrowser

import uvicorn


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000,
                        help="UI port (default 9000; avoid 8080 — the demo target uses it)")
    parser.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    parser.add_argument("--reload", action="store_true", help="auto-reload on code change (dev)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    url = f"http://{args.host}:{args.port}"
    print(f"\n  Agentic Security Platform UI -> {url}\n")
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    uvicorn.run(
        "webapp.api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
