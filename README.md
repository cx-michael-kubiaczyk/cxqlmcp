# cxqlmcp

A Go [MCP](https://modelcontextprotocol.io/) server that helps LLMs remediate false-positive findings in Checkmarx One (CxOne) SAST scans.

CxOne SAST runs CxQL queries (C# modules) against a codebase's AST to detect vulnerabilities, and those queries can be overridden per Project, per Application, or Tenant-wide. `cxqlmcp` exposes tools that let an LLM inspect a specific finding, read the CxQL query (and its override hierarchy) that produced it, understand the annotated source dataflow, iterate on a modified query against a live Checkmarx audit session, and save the fix as an override at the appropriate level — then validate the change against known true-positive/true-negative control projects so a fix doesn't break real detections or reintroduce other false positives.

> **Note:** this MCP server has mainly been tested through the companion harness at [cxql_harness](https://github.com/cx-michael-kubiaczyk/cxql_harness), rather than through a general-purpose MCP client. If you hit rough edges in a different client, that's the most likely reason.

## How remediation works

1. `create_session` from a finding URL, optionally cloning true-positive/true-negative findings as control projects.
2. Inspect the finding, its source code dataflow, and the query (plus any existing overrides) that produced it.
3. Trace and inspect any queries called by the target query.
4. Run those queries to identify where the logic needs to change.
5. Create or update an override (Project first, then Application, then Tenant) to fix the false positive.
6. Test the change, then run `scan_control_projects` or `check_control_projects` to confirm true positives still fire and no other false positives were introduced.
7. Repeat until resolved.

This flow (along with CxQL/override background) is also given to the LLM directly as the MCP server's `Instructions` string — see `HLD` in `mcp/mcp.go`.

## Tools

| Tool | Purpose |
|---|---|
| `create_session` | Initialize a remediation session from a finding URL; optionally clone TP/TN control projects. Must be called first. |
| `get_current_state` | Finding details, annotated code snippets, and the full query hierarchy in one call. |
| `get_high_level_description` | Returns the CxQL/override background and remediation workflow description. |
| `get_finding_details` | Description, risk, and remediation recommendation for the current finding. |
| `get_code_snippets` | Source files in the finding's dataflow, annotated with step markers and prior query run results. |
| `get_query_info` | CxQL source and override hierarchy (Product/Tenant/Application/Project) for a query. |
| `get_query_code` | CxQL source for a query at one specific hierarchy level. |
| `check_original_finding` | Re-runs the original query in the audit session to see if the finding still fires. |
| `check_control_projects` | Validates TP/TN control projects against their most recent scan. |
| `scan_control_projects` | Re-scans every TP/TN control project against current overrides, then validates. |
| `run_query` | Runs an existing (saved) query and returns annotated results. |
| `test_query` | Runs a modified query without saving, via a temporary override, to iterate before committing. |
| `save_query` | Saves a modified query as a permanent override at the given level. |
| `restore_query` | Reverts an override to what it was before this session's first `save_query` at that level. |
| `search_code` | Case-insensitive substring search across all scanned source files; returns matching `path:line: text` entries. |
| `search_cxql_docs` | Keyword search over the embedded CxQL API reference (CxList methods, params, examples). |
| `search_queries` | Searches all known query names for a substring, returning full `Language.Group.Name` paths. |
| `show_source_code` | Returns a line-numbered slice of a file's source (with dataflow annotations) for a given line range. |

## Layout

Two-module Go workspace:

- `/` — root binary (`github.com/cxpsemea/cxqlmcp`)
- `/mcp` — library module (`github.com/cxpsemea/cxqlmcp/mcp`): `mcp.go` registers the tools above; `tools.go` implements them
- `/mcp/backend` — session/state layer: Cx1 client, resolved entities, audit session, annotated `CodeSet`, and per-level `targetQuery` overrides

See `CLAUDE.md` for deeper architecture notes.

## Running

```bash
go build ./...

# Run the MCP server over stdio (needs Checkmarx One credentials, e.g. -apikey, or -client/-secret, plus -cx1/-iam/-tenant)
go run main.go -apikey <key> -cx1 <url> -iam <url> -tenant <tenant>

# Run the built-in scripted test harness instead of the MCP server
go run main.go --test hsts   # or --test xss
```

## Testing

```bash
go test ./mcp/backend/...
```

Requires `queries.json` (a ~3.6MB fixture pulled from a live Cx1 tenant, gitignored) at the repo root.
