"""base-mcp: bounded filesystem and HTTP tools for a sandboxed agent.

File tools are confined to an explicit list of allowed roots, and the HTTP tool
to an explicit list of allowed hosts. Both scopes are deny-by-default and
enforced here rather than in the tool arguments.

Read tools are always available. Everything that changes state - file writes,
and HTTP methods other than GET/HEAD - is registered only when EXPOSE_WRITE is
true, and is refused by name even when a client calls it directly. There is no
command-execution tool.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

import config
from config import AUDIT_LOG, log
from fs_ops import (
    _h_fs_copy,
    _h_fs_delete,
    _h_fs_edit,
    _h_fs_glob,
    _h_fs_grep,
    _h_fs_list,
    _h_fs_mkdir,
    _h_fs_move,
    _h_fs_read,
    _h_fs_read_base64,
    _h_fs_read_many,
    _h_fs_roots,
    _h_fs_stat,
    _h_fs_write,
    _h_fs_write_base64,
)
from net import _h_net_fetch

# -- Transport auth ---------------------------------------------------


# Off unless a token is configured. The credential lives in the client's
# transport config, never in a prompt or a tool argument.
def _mcp_token() -> str:
    """The expected bearer token, if transport auth is configured at all."""
    p = Path(os.getenv("MCP_AUTH_TOKEN_FILE", "/run/secrets/mcp-auth-token"))
    if p.exists():
        return p.read_text().strip()
    return os.getenv("MCP_AUTH_TOKEN", "").strip()


def _bearer_ok(header_value: str, expected: str) -> bool:
    scheme, _, presented = header_value.partition(" ")
    if scheme.lower() != "bearer":
        return False
    # Constant-time: a plain == leaks the secret by timing.
    return hmac.compare_digest(presented.strip(), expected)



# -- Error results ----------------------------------------------------


class ErrorText(str):
    """A tool result that reports a failure. call_tool sends it with isError set,
    so a client can tell it from output (a file read can itself start with
    "Error:")."""


# -- MCP server wiring ------------------------------------------------
def release_version() -> str:
    """The release this build reports to clients: BASE_MCP_VERSION,
    stamped into the image from the base-mcp-v* tag at build time, else `dev`."""
    return os.environ.get("BASE_MCP_VERSION", "").strip() or "dev"


_server = Server("base-mcp", version=release_version())

_PATH_PROP = {"type": "string", "description": "Path, absolute or relative to the first allowed root"}

_READ_TOOLS: list[Tool] = [
    Tool(name="fs_roots",
         description="Show the allowed filesystem roots and whether writes are enabled. Call this first to learn the scope.",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="fs_list",
         description="List a directory. `depth` controls recursion (1 = this directory, 0 = unlimited).",
         inputSchema={"type": "object", "properties": {
             "path": _PATH_PROP,
             "depth": {"type": "integer", "description": "Recursion depth; 0 = unlimited", "default": 1}},
             "required": ["path"]}),
    Tool(name="fs_read",
         description="Read a text file, optionally a line range (1-based, inclusive) or, for a large "
                     "file, a byte window starting at `start_byte`. The reply names the next offset "
                     "when there is more to read. Pass outline=true for the file's structure - "
                     "definitions with their line ranges - instead of its text.",
         inputSchema={"type": "object", "properties": {
             "path": _PATH_PROP,
             "start_line": {"type": "integer", "description": "First line; 0 = from the start", "default": 0},
             "end_line": {"type": "integer", "description": "Last line; 0 = to the end", "default": 0},
             "start_byte": {"type": "integer", "description": "Byte offset to read from; cannot be combined with a line range", "default": 0},
             "outline": {"type": "boolean", "description": "Return the file's structure - definitions with their line ranges - instead of its text. Combine with a line range to map just that region.", "default": False}},
             "required": ["path"]}),
    Tool(name="fs_glob",
         description="Find paths under a directory by glob (supports `**`), e.g. `src/**/*.py`.",
         inputSchema={"type": "object", "properties": {
             "path": _PATH_PROP,
             "pattern": {"type": "string", "description": "Glob relative to `path`"}},
             "required": ["path", "pattern"]}),
    Tool(name="fs_grep",
         description="Search files under a path for a regex; returns line-numbered matches.",
         inputSchema={"type": "object", "properties": {
             "path": _PATH_PROP,
             "pattern": {"type": "string", "description": "Regex to search for"},
             "include": {"type": "string", "description": "Only search files matching this glob, e.g. '*.py'", "default": ""},
             "ignore_case": {"type": "boolean", "description": "Case-insensitive", "default": False}},
             "required": ["path", "pattern"]}),
    Tool(name="fs_read_many",
         description="Read several text files in one call. A path that cannot be read reports inline; the rest still return.",
         inputSchema={"type": "object", "properties": {
             "paths": {"type": "array", "items": {"type": "string"}, "description": "Paths to read"}},
             "required": ["paths"]}),
    Tool(name="fs_read_base64",
         description="Read any file as base64, including binary ones (images, archives).",
         inputSchema={"type": "object", "properties": {"path": _PATH_PROP}, "required": ["path"]}),
    Tool(name="fs_stat",
         description="Show kind, size, mode and mtime for a path.",
         inputSchema={"type": "object", "properties": {"path": _PATH_PROP}, "required": ["path"]}),
    Tool(name="net_fetch",
         description="Make an HTTP request to an allow-listed host and return the response. "
                     "GET and HEAD are always available; other methods require the server to be "
                     "started with writes enabled. Redirects are followed only to allow-listed hosts.",
         inputSchema={"type": "object", "properties": {
             "url": {"type": "string", "description": "Absolute http(s) URL"},
             "method": {"type": "string", "description": "GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS", "default": "GET"},
             "headers": {"type": "object", "description": "Extra request headers", "default": {}},
             "body": {"type": "string", "description": "Request body, for methods that take one", "default": ""},
             "max_bytes": {"type": "integer", "description": "Cap on returned body bytes; 0 = server default", "default": 0}},
             "required": ["url"]}),
]

_WRITE_TOOLS: list[Tool] = [
    Tool(name="fs_write",
         description="Write a text file, creating parent directories. Set `append` to add to an existing file.",
         inputSchema={"type": "object", "properties": {
             "path": _PATH_PROP,
             "content": {"type": "string", "description": "File content"},
             "append": {"type": "boolean", "description": "Append instead of replacing", "default": False}},
             "required": ["path", "content"]}),
    Tool(name="fs_edit",
         description="Replace an exact string in a file. The match is literal and must be unique unless "
                     "`replace_all` is set; include surrounding lines to disambiguate. Prefer this over "
                     "rewriting a whole file with fs_write.",
         inputSchema={"type": "object", "properties": {
             "path": _PATH_PROP,
             "old_string": {"type": "string", "description": "Exact text to replace, whitespace included"},
             "new_string": {"type": "string", "description": "Replacement text"},
             "replace_all": {"type": "boolean", "description": "Replace every occurrence", "default": False}},
             "required": ["path", "old_string", "new_string"]}),
    Tool(name="fs_write_base64",
         description="Write a file from base64 content, for binary files.",
         inputSchema={"type": "object", "properties": {
             "path": _PATH_PROP,
             "content_base64": {"type": "string", "description": "Base64-encoded file content"}},
             "required": ["path", "content_base64"]}),
    Tool(name="fs_copy",
         description="Copy a file, or a directory with `recursive`. Both ends must be inside the allowed roots.",
         inputSchema={"type": "object", "properties": {
             "src": {"type": "string", "description": "Existing path"},
             "dest": {"type": "string", "description": "New path; must not already exist"},
             "recursive": {"type": "boolean", "description": "Required to copy a directory", "default": False}},
             "required": ["src", "dest"]}),
    Tool(name="fs_mkdir",
         description="Create a directory (and any missing parents).",
         inputSchema={"type": "object", "properties": {"path": _PATH_PROP}, "required": ["path"]}),
    Tool(name="fs_move",
         description="Move or rename a path. Both ends must be inside the allowed roots.",
         inputSchema={"type": "object", "properties": {
             "src": {"type": "string", "description": "Existing path"},
             "dest": {"type": "string", "description": "New path; must not already exist"}},
             "required": ["src", "dest"]}),
    Tool(name="fs_delete",
         description="Delete a file, or a directory with `recursive`.",
         inputSchema={"type": "object", "properties": {
             "path": _PATH_PROP,
             "recursive": {"type": "boolean", "description": "Required to delete a directory", "default": False}},
             "required": ["path"]}),
]

_WRITE_TOOL_NAMES = frozenset(t.name for t in _WRITE_TOOLS)


async def list_tools(_ctx: Any, _params: PaginatedRequestParams) -> ListToolsResult:
    # Composed per call so a test can flip EXPOSE_WRITE without reimporting.
    return ListToolsResult(tools=_READ_TOOLS + (_WRITE_TOOLS if config.EXPOSE_WRITE else []))


# Only these argument keys are ever logged; file content, request bodies and
# headers never reach the log.
_AUDIT_ARGS = (
    "path", "src", "dest", "url", "method", "pattern", "include",
    "recursive", "append", "replace_all", "start_line", "end_line", "start_byte",
)


def _audit(name: str, args: dict, outcome: str, ms: float, detail: str = "") -> None:
    if not AUDIT_LOG:
        return
    record: dict[str, Any] = {"tool": name, "outcome": outcome, "ms": round(ms, 1)}
    record.update({k: args[k] for k in _AUDIT_ARGS if k in args})
    if "paths" in args:
        record["paths"] = len(args["paths"]) if isinstance(args["paths"], list) else "?"
    if detail:
        record["detail"] = detail[:200]
    log.info(json.dumps(record, default=str))


async def call_tool(_ctx: Any, params: CallToolRequestParams) -> CallToolResult:
    started = time.perf_counter()
    args = params.arguments or {}
    detail = ""
    structured: dict | None = None
    try:
        result = await _dispatch(params.name, args)
        # A handler that had to cut returns structured content alongside the text.
        if isinstance(result, tuple):
            result, structured = result
        # A refusal from the gate comes back as ErrorText rather than an
        # exception, so it is classified here to keep both refusal paths in one
        # log field.
        outcome = "refused" if isinstance(result, ErrorText) else "ok"
        detail = result[:200] if outcome == "refused" else ""
    except ValueError as exc:  # every containment and policy check raises this
        result = ErrorText(f"Error: {exc}")
        outcome, detail = "refused", str(exc)
    except Exception as exc:  # noqa: BLE001 - surface as a tool error, don't crash the server
        result = ErrorText(f"Error: {exc}")
        outcome, detail = "error", str(exc)
    _audit(params.name, args, outcome, (time.perf_counter() - started) * 1000, detail)
    return CallToolResult(
        content=[TextContent(type="text", text=result)],
        structured_content=structured,
        is_error=isinstance(result, ErrorText),
    )


# Each registration names the wire method and the params model the runner
# validates against before the handler is called.
_server.add_request_handler("tools/list", PaginatedRequestParams, list_tools)
_server.add_request_handler("tools/call", CallToolRequestParams, call_tool)


async def _dispatch(name: str, a: dict) -> str | tuple[str, dict]:
    # Gate by name before dispatch: a client that cached or guessed the name is
    # refused here.
    if name in _WRITE_TOOL_NAMES and not config.EXPOSE_WRITE:
        return ErrorText(f"Error: {name} is disabled (EXPOSE_WRITE=false)")
    if name == "fs_roots":
        return _h_fs_roots()
    if name == "fs_list":
        return _h_fs_list(a["path"], int(a.get("depth", 1)))
    if name == "fs_read":
        return _h_fs_read(
            a["path"], int(a.get("start_line", 0)), int(a.get("end_line", 0)),
            int(a.get("start_byte", 0)), bool(a.get("outline", False)),
        )
    if name == "fs_glob":
        return _h_fs_glob(a["path"], a["pattern"])
    if name == "fs_grep":
        return _h_fs_grep(a["path"], a["pattern"], a.get("include", ""), bool(a.get("ignore_case", False)))
    if name == "fs_stat":
        return _h_fs_stat(a["path"])
    if name == "fs_read_many":
        return _h_fs_read_many(a["paths"])
    if name == "fs_read_base64":
        return _h_fs_read_base64(a["path"])
    if name == "fs_write":
        return _h_fs_write(a["path"], a["content"], bool(a.get("append", False)))
    if name == "fs_edit":
        return _h_fs_edit(a["path"], a["old_string"], a["new_string"], bool(a.get("replace_all", False)))
    if name == "fs_write_base64":
        return _h_fs_write_base64(a["path"], a["content_base64"])
    if name == "fs_copy":
        return _h_fs_copy(a["src"], a["dest"], bool(a.get("recursive", False)))
    if name == "fs_mkdir":
        return _h_fs_mkdir(a["path"])
    if name == "fs_move":
        return _h_fs_move(a["src"], a["dest"])
    if name == "fs_delete":
        return _h_fs_delete(a["path"], bool(a.get("recursive", False)))
    if name == "net_fetch":
        return await _h_net_fetch(
            a["url"], a.get("method", "GET"), a.get("headers") or {},
            a.get("body", ""), int(a.get("max_bytes", 0)),
        )
    return ErrorText(f"Error: unknown tool '{name}'")


# -- Entry point ------------------------------------------------------
async def _send_401(send: Any) -> None:
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [
            (b"www-authenticate", b'Bearer realm="base-mcp"'),
            (b"content-type", b"text/plain; charset=utf-8"),
        ],
    })
    await send({"type": "http.response.body", "body": b"unauthorized"})


class _BearerAuth:
    """Require a bearer token on the MCP endpoints, when one is configured.

    Plain ASGI so the check sits in front of routing: an unauthenticated
    request never opens an SSE stream. `/healthz` stays open for container
    probes.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope.get("path") != "/healthz":
            expected = _mcp_token()
            if expected:
                presented = ""
                for key, value in scope.get("headers", []):
                    if key.lower() == b"authorization":
                        presented = value.decode("latin-1")
                        break
                if not _bearer_ok(presented, expected):
                    _audit("_transport", {"path": scope.get("path", "")}, "unauthenticated", 0.0,
                           "missing or invalid bearer token")
                    await _send_401(send)
                    return
        await self.app(scope, receive, send)


def build_sse_app():
    """Build the Starlette ASGI app for the SSE transport. A separate function so tests
    can construct it. Startup and shutdown use the ``lifespan`` context manager, a
    plain passthrough here.
    """
    from contextlib import asynccontextmanager

    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse
    from starlette.routing import Mount, Route

    sse = SseServerTransport("/messages/")

    async def health(_request: Request) -> PlainTextResponse:
        # A liveness target that is not /sse: probing the SSE endpoint opens a
        # streaming connection the prober never closes cleanly.
        return PlainTextResponse("ok")

    async def handle_sse(request: Request) -> None:
        async with sse.connect_sse(request.scope, request.receive, request._send) as (rs, ws):
            await _server.run(rs, ws, _server.create_initialization_options())

    @asynccontextmanager
    async def lifespan(_app):
        yield

    return Starlette(
        routes=[
            Route("/healthz", endpoint=health),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
        middleware=[Middleware(_BearerAuth)],
        lifespan=lifespan,
    )


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport == "sse":
        import uvicorn

        uvicorn.run(
            build_sse_app(),
            host=os.getenv("MCP_HOST", "0.0.0.0"),
            port=int(os.getenv("MCP_PORT", "3000")),
        )
    else:
        async def _run_stdio() -> None:
            from mcp.server.stdio import stdio_server
            async with stdio_server() as (rs, ws):
                await _server.run(rs, ws, _server.create_initialization_options())

        asyncio.run(_run_stdio())
