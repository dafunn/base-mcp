# base-mcp

Bounded filesystem and HTTP tools for an agent that runs in a locked-down
container. File tools are confined to an explicit list of allowed roots; the
HTTP tool is confined to an explicit list of allowed hosts. Both scopes are
deny-by-default and enforced in the server, so the model cannot widen them by
argument. Served over stdio or SSE with the low-level `mcp.server.Server`.

There is deliberately no command-execution tool: one would undo every
restriction the others enforce.

## Tools

Always available:

- `fs_roots()` - the allowed roots, and whether writes are enabled.
- `fs_list(path, depth?)` - directory listing; `depth=1` is one level, `0` is unlimited.
- `fs_read(path, start_line?, end_line?, start_byte?)` - read a text file by line
  range, or page a large one by byte offset; the reply names the next offset.
- `fs_glob(path, pattern)` - find paths by glob (supports `**`).
- `fs_grep(path, pattern, include?, ignore_case?)` - line-numbered regex matches.
- `fs_read_many(paths)` - read several files in one call; a bad path reports inline.
- `fs_read_base64(path)` - read any file as base64, including binary ones.
- `fs_stat(path)` - kind, size, mode, mtime.
- `net_fetch(url, method?, headers?, body?, max_bytes?)` - HTTP request to an
  allow-listed host. `GET` and `HEAD` always; other methods only with writes enabled.

Registered only when `EXPOSE_WRITE=true`, and refused by name otherwise even if
a client calls them directly:

- `fs_write(path, content, append?)` - write a text file, creating parents.
- `fs_edit(path, old_string, new_string, replace_all?)` - replace an exact string.
- `fs_write_base64(path, content_base64)` - write a binary file.
- `fs_copy(src, dest, recursive?)` - copy a file or directory.
- `fs_mkdir(path)` - create a directory.
- `fs_move(src, dest)` - move or rename; both ends must be inside the roots.
- `fs_delete(path, recursive?)` - delete a file, or a directory with `recursive`.

Paths may be absolute or relative to the first allowed root.

`fs_edit` matches literally, not by regex, and refuses a non-unique match unless
`replace_all` is set. It also refuses a file that is not valid UTF-8, since the
edit writes the decoded text back.

## Config (env)

| var | default | meaning |
| --- | --- | --- |
| `MCP_TRANSPORT` | `stdio` | set `sse` to serve over HTTP |
| `MCP_HOST` / `MCP_PORT` | `0.0.0.0` / `3000` | SSE bind |
| `FS_ALLOW_ROOTS` | _(empty: deny all)_ | comma-separated absolute paths, e.g. `/workspace,/data` |
| `FS_DENY_GLOBS` | see below | paths never served, even inside a root |
| `FS_READONLY_ROOTS` | _(empty)_ | roots served for reading but refused for writing |
| `EXPOSE_WRITE` | `false` | register the write tools, and allow non-safe HTTP methods |
| `FS_MAX_FILE_BYTES` | `200000` | read cap per file |
| `FS_MAX_WRITE_BYTES` | `1000000` | write cap per call |
| `FS_MAX_ENTRIES` | `2000` | cap on listing / glob results |
| `FS_MAX_GREP_MATCHES` | `200` | cap on grep matches |
| `FS_MAX_READ_FILES` | `20` | cap on paths per `fs_read_many` call |
| `NET_ALLOW_HOSTS` | _(empty: deny all)_ | comma-separated hosts; a leading dot allows subdomains, e.g. `api.example.com,.example.org` |
| `NET_ALLOW_PRIVATE_ADDRS` | `false` | allow hosts that resolve to private, loopback or link-local addresses |
| `NET_PIN_ADDRESS` | `true` | connect to the address the policy check validated |
| `NET_MAX_BYTES` | `200000` | cap on returned body bytes |
| `NET_TIMEOUT_SECONDS` | `30` | HTTP timeout |
| `NET_MAX_REDIRECTS` | `3` | redirect hops, each re-checked against the allowlist |
| `NET_AUTH_HOSTS` | _(empty: none)_ | hosts the server attaches a credential to; same matching rules as the allowlist |
| `NET_AUTH_TOKEN_FILE` | `/run/secrets/net-auth-token` | credential file (falls back to `NET_AUTH_TOKEN`) |
| `NET_AUTH_HEADER` / `NET_AUTH_SCHEME` | `Authorization` / `Bearer` | header and scheme used to send it |
| `MCP_AUTH_TOKEN_FILE` | `/run/secrets/mcp-auth-token` | bearer token for the SSE endpoints (falls back to `MCP_AUTH_TOKEN`); unset means no transport auth |
| `AUDIT_LOG` | `true` | one JSON line per tool call on stderr |
| `LOG_LEVEL` | `INFO` | log level |

`FS_READONLY_ROOTS` names roots that may be read and not changed. `fs_roots`
reports them, and a refusal names the policy rather than a bare `EPERM`. Mount
them read-only as well. Copying out of a read-only root is allowed; moving out of
one is not, because a move removes the source.

An empty allowlist denies rather than defaults: a server given no roots serves
no file, and one given no hosts makes no request. A root must be an absolute
path, or the server refuses to start - resolving a relative root against the
process working directory would make the scope depend on how the container was
launched.

`FS_DENY_GLOBS` defaults to the usual homes of credentials (`**/.env`,
`**/.ssh/**`, `**/.git/**`, `**/*.pem`, `**/id_rsa*`, and similar). Patterns are
fnmatch-style over the whole path, so `*` crosses separators; a matching
directory hides everything beneath it. Setting the variable replaces the
defaults rather than adding to them.

## What is enforced

- Every path is resolved with symlinks followed and `..` collapsed, then checked
  against the roots. A traversal argument and a symlink pointing out of a root
  fail the same check. Listings show symlinks but never follow them.
- The deny globs are applied to the resolved path and each of its parents, so a
  denied directory cannot be entered by naming a child directly.
- Host allowlist entries are exact unless written with a leading dot. Glob
  matching is deliberately not offered: a pattern that reads as "the example.com
  site" also matches `notexample.com`.
- Hosts are resolved before the request and rejected if any address is private,
  loopback, link-local, reserved or multicast, unless `NET_ALLOW_PRIVATE_ADDRS`
  is set. This is what keeps an allow-listed name that happens to resolve inward
  from reaching a neighbouring service or a metadata endpoint.
- Writes go through a temp file in the same directory and a rename, so an
  interrupted write leaves the previous content rather than a truncated file.
  Directory copies skip denied entries and copy symlinks as symlinks, rather
  than dereferencing them and pulling in whatever they point at.
- Redirects are followed one hop at a time and each destination is re-checked
  against the allowlist, since an allow-listed host redirecting inward is the
  ordinary shape of a server-side request forgery. A relative `Location` is
  resolved against the hostname, not against the pinned address.
- The host is resolved once, and the request connects to that exact address, so
  a name that changes its answer between the check and the connection cannot
  land somewhere the check never saw. The Host header and the TLS SNI still
  carry the hostname, so virtual hosting and certificate verification work
  normally. A host with several addresses gets the first one and no failover;
  set `NET_PIN_ADDRESS=false` where something in front needs the name resolved
  at connect time.

None of this replaces a network boundary around the container.

## Credentials

Set `NET_AUTH_HOSTS` and mount the token at `NET_AUTH_TOKEN_FILE`, and the
server attaches the auth header itself to requests for those hosts. The token
never appears in a tool result, a tool argument, or the audit log. A request that
sets the auth header itself is refused.

The credential is recomputed per redirect hop, so a redirect to a host outside
`NET_AUTH_HOSTS` drops it instead of forwarding it.

## Transport auth

Under SSE the server serves `/sse` and `/messages/` to whoever can reach it, so
by default the boundary is the network around it.

Configure `MCP_AUTH_TOKEN_FILE` (or `MCP_AUTH_TOKEN`) to also require
`Authorization: Bearer <token>` on both endpoints. The check runs in front of
routing, so an unauthenticated request never opens a stream, and the comparison
is constant-time. `/healthz` stays open for container probes.

The token goes in the client's transport configuration; it is not a tool argument
and never reaches the model.

## Audit log

With `AUDIT_LOG` on, every tool call writes one JSON line to stderr: the tool
name, the outcome (`ok`, `refused`, `error`), how long it took, and a fixed set
of argument keys - paths, URLs, methods, flags. File content, request bodies and
headers are never logged. The key list is an allowlist rather than a denylist,
so a tool that grows a new argument cannot leak it into the log by default.

```
{"tool": "fs_read", "outcome": "refused", "ms": 0.3, "path": ".env", "detail": "Error: path '.env' is blocked by deny pattern '**/.env'"}
```

## Build / run

```
docker build -t base-mcp .

FS_ALLOW_ROOTS=/workspace \
NET_ALLOW_HOSTS=.example.com \
MCP_TRANSPORT=sse \
.venv/bin/python server.py   # after `uv sync --frozen` (Python 3.14 and uv)
```

The server reports its release in the MCP `initialize` result
(`serverInfo.version`). To stamp it, build from a checkout with tags:

```
docker build --build-arg BASE_MCP_VERSION=$(git describe --tags --match 'base-mcp-v*' | sed 's/^base-mcp-v//') .
```

A build without it reports `dev`.

## As a client's only way out

Put the client on an internal network with only this server, and attach the
server to a second network that reaches the outside. The server is then the
client's only route out.

```yaml
networks:
  tools:              # client <-> server; no route off the host
    internal: true
  egress: {}          # this server's way out

services:
  client:
    image: your-agent
    networks: [tools]
    # its MCP client points at http://base-mcp:3000/sse

  base-mcp:
    image: base-mcp
    networks: [tools, egress]
    volumes: ["workspace:/workspace"]
    environment:
      MCP_TRANSPORT: sse
      FS_ALLOW_ROOTS: /workspace
      NET_ALLOW_HOSTS: .example.com
      EXPOSE_WRITE: "true"

volumes:
  workspace:
```

A named volume as above needs no ownership work. To bind-mount a host directory
under a rootless runtime, build with `--build-arg APP_UID=$(id -u)` and run the
container with a matching user namespace, or the write tools hit permission
errors that the tool output cannot explain.

Use two networks, not one shared network namespace: containers in the same
namespace share its reachability, so the client could reach anything the server
can.

Under SSE the server also serves `GET /healthz`, which is the endpoint to point
a container probe at - probing `/sse` opens a stream the prober never closes
cleanly.

The compose file above is an illustration; this repository ships the server
only.

Tests: `uv sync --frozen --extra dev && .venv/bin/python -m pytest tests/`
