# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Does

`cxqlmcp` is a Go MCP (Model Context Protocol) server that helps LLMs remediate false-positive findings in Checkmarx One (CxOne) SAST scans. It exposes tools for inspecting CxQL queries, viewing annotated source code dataflows, running modified queries against live audit sessions, and creating/updating query overrides at different hierarchy levels (Product → Tenant → Application → Project).

## Module Layout

This is a **two-module Go workspace**:

- `/go.mod` — root binary (`github.com/cxpsemea/cxqlmcp`)
- `/mcp/go.mod` — sub-module library (`github.com/cxpsemea/cxqlmcp/mcp`), pulled into the root module via a `replace` directive to `./mcp`

Both modules depend on `github.com/cxpsemea/Cx1ClientGo` as a normal versioned dependency (no local sibling checkout required). Build and test commands must be run separately per module when needed.

## Build & Test Commands

```bash
# Build everything from root
go build ./...

# Run tests (the only tests are in mcp/backend)
go test ./mcp/backend/...
go test -v ./mcp/backend/...

# Run a specific test
go test -v ./mcp/backend/... -run TestName

# Run the MCP server over stdio (requires Cx1 credentials in environment)
go run main.go

# Run the built-in dev test harness instead of the MCP server
go run main.go --test hsts   # or --test xss
```

The `util_test.go` tests require `queries.json` (3.6 MB fixture, gitignored). This file must be obtained separately from Cx1 — tests will fail without it. `queries.json` is loaded using relative paths `"../queries.json"` and `"../../queries.json"`, depending on the test.

## Architecture

### Three-layer design

**`main.go`** — Entry point. Sets up logging, initializes the HTTP client and `Cx1Client` (credentials read from env vars via `Cx1ClientGo.NewClient`), constructs the `mcp.MCP` server, and either runs the stdio MCP server (`server.Start()`) or, if `--test hsts|xss` is passed, runs a hardcoded scripted harness (`runTest` / `testXSS` / `testHSTS`) against a live Cx1 tenant for manual exploration.

**`mcp/` (tools layer)** — `mcp.go` defines the `MCP` struct, the `HLD` string (a multi-paragraph prompt injected as the MCP server's `Instructions`, explaining CxQL, the override hierarchy, and the FP remediation workflow), and `registerTools()`, which registers every LLM-facing tool (`create_session`, `get_current_state`, `get_query_info`, `run_query`, `test_query`, `save_query`, etc.) with typed input structs via `mcpsdk.AddTool`. `tools.go` implements the corresponding `MCP` methods that back those tools.

**`mcp/backend/` (backend layer)** — `MCPBackend` struct holds session state: the `Cx1Client`, resolved project/application/scan entities, the `ScanSASTResult` being investigated, the `AuditSession`, a `CodeSet` of annotated source files, and `targetQuery []*SASTQuery` (one slot per hierarchy level).

### Key non-obvious details

- **Proxy hardcoded in `main.go`**: a dev-only MITM proxy block (`http://127.0.0.1:8080`, `InsecureSkipVerify: true`) is gated behind `if false { ... }`. Flip to `true` locally to inspect Cx1 API traffic; never commit it enabled.

- **`flag.Parse()` never called**: `--log` and `--test` are registered with `flag.String` but `flag.Parse()` is not invoked, so both flags are permanently stuck at their defaults (`--log` always resolves to `INFO`) regardless of what's passed on the command line.

- **MCP transport is wired**: `MCP.Start()` runs `m.server.Run(ctx, &mcpsdk.StdioTransport{})` — this is a real stdio MCP server, not a stub. Logging is sent to stderr specifically so it doesn't corrupt the stdio transport on stdout.

- **`SearchCode()` and `ShowSourceCode()`** in `tools.go` are still stubs (return `""`). Everything else is implemented: true-positive/true-negative "control projects" are cloned into a scratch test application by `CreateTestEnvironment`, exposed to the LLM as the `check_control_projects` (validate against each control project's most recent scan) and `scan_control_projects` (re-scan every control project against the current query overrides, then validate) tools, backed by `backend.CheckControlProjects`/`backend.ScanControlProjects`. Source zips downloaded via `GetScanSourcesByID` are cached on disk under `./data/<scanID>.zip` (`backend.getScanSourceZip`) so re-scanning a control project doesn't re-download its source.

- **Query hierarchy index convention**: `GetQueryHierarchy` always returns `[product, tenant, application, project]` (indices 0–3). Nil means no override at that level. `FormatQueryHierarchy` and `closestQuery` depend on this convention.

- **Code annotation system** (`filesource.go`): `FileSource` stores source lines plus an `Augs` map from line number → `AugmentSource` → `[]string`. `Code()` renders source with inline `// AugmentSource: message` comments. `AugSrc_Finding(query)` marks nodes from the original scan dataflow; `AugSrc_Audit(query)` marks nodes from an audit query run (`VulnAugment`) or inline query errors (`processRunFailures` in `tools.go`).

- **`findingsEqual` (`util.go`)**: compares a `ScanSASTResult`'s nodes against a `QueryVulnerability`'s nodes index-by-index and returns `true` on the **first matching index**, not requiring the whole path to match — a false match is possible whenever two dataflows happen to agree at any single node position. The bounds check (`i > len(v.Nodes)`) is also off-by-one for the final index.

- **`registerTools` input structs are the API contract**: tool argument shapes (e.g. `queryInput`, `testQueryInput`) are defined inline as anonymous structs in `mcp.go` right next to each `mcpsdk.AddTool` call — check there first when changing a tool's parameters, not just in `tools.go`.
