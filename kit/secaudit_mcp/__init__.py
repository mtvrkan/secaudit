"""SecAudit as an MCP server — the same engine, reachable from any MCP client.

Claude Code gets SecAudit as a plugin. Everything else — Codex, Cursor, OpenCode, Copilot CLI,
Zed, or anything that speaks the Model Context Protocol — gets it through this. One engine, one
set of measured numbers, one place a bug gets fixed. A second implementation per harness is how
two clients end up disagreeing about whether a file is safe.

Deliberately narrow. Only the tools that need no authorization gate are exposed: reading source
you already have, reading a manifest you already have, and describing what the engine can and
cannot see. Active checks against a running target stay behind the plugin's `scope.yaml`
authorization flow, because consent to scan a live system is a human decision and an MCP tool
call is not a place to record one.
"""
from .server import TOOLS, handle, serve   # noqa: F401

__all__ = ["TOOLS", "handle", "serve"]
