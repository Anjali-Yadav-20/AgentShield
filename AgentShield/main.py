"""
main.py
AgentShield entry point.

Run with:
    python main.py
"""

import sys

from database import initialize_database


def main():
    initialize_database()
    try:
        from ui import run_app
    except ImportError as exc:
        print("AgentShield requires PySide6 to run the desktop UI.")
        print(f"Import error: {exc}")
        print("Install it with:  pip install PySide6")
        sys.exit(1)

    run_app()


if __name__ == "__main__":
    main()
