#!/usr/bin/env python3
"""EXAMINER - Advanced Reconnaissance Tool (entry point).

Developed by: Ahmed Ekramy
"""
import sys

if sys.version_info < (3, 8):
    sys.stderr.write("EXAMINER requires Python 3.8 or newer.\n")
    sys.exit(1)

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main(argv=None) -> int:
    from core.constants import APP_AUTHOR, APP_NAME, APP_TAGLINE, APP_VERSION
    from utils.helpers import configure_stdio

    parser = argparse.ArgumentParser(
        prog="examiner", description=f"{APP_NAME} - {APP_TAGLINE} (by {APP_AUTHOR})")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--check-deps", action="store_true",
                        help="print dependency status and exit")
    args = parser.parse_args(argv)

    configure_stdio()
    try:
        from core.engine import Engine
        engine = Engine(ROOT, no_color=args.no_color)
        if args.check_deps:
            return engine.print_dependency_report()
        return engine.run()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Goodbye!")
        return 130
    except Exception as exc:  # noqa: BLE001 - last-resort safety net
        import logging
        logging.getLogger("examiner").exception("Fatal error")
        print(f"\n[-] Fatal error: {exc}\n    Details were written to the log file.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
