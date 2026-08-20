"""`python3 -m secaudit_mcp` — the command every MCP client config points at."""
import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main())
