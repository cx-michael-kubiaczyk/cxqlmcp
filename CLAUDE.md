# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Does

`cxqlmcp` is a Go MCP (Model Context Protocol) server that helps LLMs remediate false-positive findings in Checkmarx One (CxOne) SAST scans. It exposes tools for inspecting CxQL queries, viewing annotated source code dataflows, running modified queries against live audit sessions, and creating/updating query overrides at different hierarchy levels (Product → Tenant → Application → Project).

## Module Layout

This is a **two-module Go workspace**:

- `/go.mod` — root binary (`github.com/cxpsemea/cxqlmcp`)
- `/mcp/go.mod` — sub-module library (`github.com/cxpsemea/cxqlmcp/mcp`)

Both modules use a `replace` directive pointing `github.com/cxpsemea/Cx1ClientGo v0.1.59` to `../Cx1ClientGo`, a sibling directory that must be checked out locally. Build and test commands must be run separately per module when needed.

## Build & Test Commands

```bash
# Build everything from root
go build ./...

# Run tests (the only tests are in mcp/backend)
go test ./mcp/backend/...
go test -v ./mcp/backend/...

# Run a specific test
go test -v ./mcp/backend/... -run TestName

# Run the binary (requires Cx1 credentials in environment)
go run main.go
```

The `util_test.go` tests require `queries.json` (3.6 MB fixture, gitignored). This file must be obtained separately from Cx1 — tests will fail without it. `queries.json` is loaded using relative paths `"../queries.json"` and `"../../queries.json"`.

## Architecture

### Three-layer design

**`main.go`** — Entry point. Initializes the HTTP client, `Cx1Client` (credentials read from env vars), creates the MCP struct, and calls `runTest()` (a development harness, not a real MCP server yet).

**`mcp/` (tools layer)** — `MCP` struct exposes the LLM-facing tool methods. `mcp.go` defines the struct and an `HLD` string (a multi-paragraph prompt injected into LLM context explaining CxQL, the override hierarchy, and the FP remediation workflow). `tools.go` implements all tool methods.

**`mcp/backend/` (backend layer)** — `MCPBackend` struct holds session state: the `Cx1Client`, resolved project/application/scan entities, the `ScanSASTResult` being investigated, the `AuditSession`, a `CodeSet` of annotated source files, and `targetQuery [4]*SASTQuery` (one slot per hierarchy level).

### Key non-obvious details

- **Proxy hardcoded in `main.go`**: `http://127.0.0.1:8080` with `InsecureSkipVerify: true` is enabled via `if true { ... }` — development convenience for a local MITM proxy. Must be disabled before any production use.

- **`flag.Parse()` never called**: The `--log` flag is registered but `flag.Parse()` is not called, so the log level is permanently `INFO` regardless of the flag.

- **MCP protocol not yet wired**: `Start()` is a no-op. The project is building tool logic; the stdio/SSE MCP transport layer is not yet implemented.

- **`SaveQuery()`, `SearchCode()`, `ShowSourceCode()`** in `tools.go` are stubs — not yet implemented.

- **Query hierarchy index convention**: `GetQueryHierarchy` always returns `[product, tenant, application, project]` (indices 0–3). Nil means no override at that level. `FormatQueryHierarchy` and `closestQuery` depend on this convention.

- **Code annotation system** (`filesource.go`): `FileSource` stores source lines plus an `Augs` map from line number → `AugmentSource` → `[]string`. `Code()` renders source with inline `// AugmentSource: step N` comments. `AugmentSource` distinguishes "Finding X" annotations (from the original scan dataflow) from "Query Y" annotations (from audit run results).

- **`TempCode` field**: When `RunQuery` is called, the source under test is stored in `MCPBackend.TempCode`. `processAuditResults` uses this to match error locations back to the code being tested rather than the stored query code.

- **`findingsEqual` limitation**: Compares `ScanSASTResult` nodes against `QueryVulnerability` nodes by checking only the first node's file/line/column/name. May produce false matches if multiple findings share the same first node.
