package mcp

import (
	"context"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/cxpsemea/cxqlmcp/mcp/backend"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"
)

type MCP struct {
	backend backend.MCPBackend
	logger  *logrus.Logger
	HLD     string // high-level description of the query process
	server  *mcpsdk.Server
	cancel  context.CancelFunc
}

func NewMCP(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) *MCP {
	m := &MCP{
		logger:  logger,
		backend: backend.NewBackend(cx1client, logger),
		HLD: `When a CxSAST scan runs, various "CxQL queries" (written as C# code modules) are run against an AST (abstract syntax tree) representation of a codebase.
Each query returns a list of items representing nodes or dataflow paths through the AST.
The CxSAST product includes a variety of queries covering a range of security vulnerabilities, such as Reflected XSS or SQL Injection.
Queries that represent security vulnerabilities can call other queries to assemble the dataflows from the 'source node' to the 'sink node' in the AST.
Most queries can be 'overridden' allowing users to change the behavior of a specific query for a specific Project (a codebase), for an Application (a collection of Projects), or across the entire Tenant in the platform.
Query execution can also be chained, so a Tenant-wide override of Reflected_XSS can call the product default version via: result = base.Reflected_XSS();
Chained execution can go across levels, so a Project-level override can call an Application-level override which can call the Tenant-level override which can call the product default version.
When addressing false-positive results in a finding, the process follows these steps:
1. Examine the source code involved in the dataflow for the false-positive result.
2. Examine the target query generating the false-positive result to see the query source code, any existing overrides, and any other queries that the target query calls.
3. Examine any other queries and their overrides if they are part of the target query's call chains.
4. Run any queries involved in the target query's call chain to identify points of improvement.
5. Update existing overrides, or create new overrides (preferring Project-level overrides first, then Application, then Tenant) to improve the results and address the original false positive result.
6. Test the updated queries to evaluate the result.
7. Repeat the process as needed until the false positive is removed.
`,
	}

	m.server = mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "cxqlmcp",
		Version: "v1.0.0",
	}, &mcpsdk.ServerOptions{
		Instructions: m.HLD,
	})
	m.registerTools()
	return m
}

func textResult(s string) *mcpsdk.CallToolResult {
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: s}},
	}
}

func (m *MCP) registerTools() {
	type urlInput struct {
		Path string `json:"path" jsonschema:"Full URL of the Checkmarx One SAST finding result page"`
	}
	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "create_session",
		Description: "Initialize a remediation session from a Checkmarx One SAST finding URL. Must be called before any other tool.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, input urlInput) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.CreateSessionFromURL(input.Path)), nil, nil
	})

	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "get_current_state",
		Description: "Returns finding details, annotated source code snippets, and the full CxQL query hierarchy in one call.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, _ struct{}) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.GetCurrentState()), nil, nil
	})

	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "get_high_level_description",
		Description: "Returns a high-level description of the query override process and query behavior.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, _ struct{}) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.GetHLD()), nil, nil
	})

	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "get_finding_details",
		Description: "Returns the description, risk, and remediation recommendation for the current finding.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, _ struct{}) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.GetFindingDetails()), nil, nil
	})

	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "get_code_snippets",
		Description: "Returns source code files involved in the finding's dataflow path, annotated with step markers and any prior query run results.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, _ struct{}) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.GetCodeSnippets()), nil, nil
	})

	type queryInput struct {
		Language string `json:"language" jsonschema:"CxQL language name, e.g. Java or JavaScript"`
		Group    string `json:"group" jsonschema:"CxQL query group name, e.g. Java_High_Risk"`
		Name     string `json:"name" jsonschema:"CxQL query name, e.g. Reflected_XSS"`
	}
	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "get_query_info",
		Description: "Returns the CxQL source code and override hierarchy (Product/Tenant/Application/Project levels) for a query.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, input queryInput) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.GetQueryInfo(input.Language, input.Group, input.Name)), nil, nil
	})

	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "check_original_finding",
		Description: "Re-runs the original query in the audit session to determine whether the finding is still present.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, _ struct{}) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.CheckOriginalFinding()), nil, nil
	})

	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "run_query",
		Description: "Runs an existing CxQL query at its current saved state and returns results with annotated source code.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, input queryInput) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.RunQuery(input.Language, input.Group, input.Name)), nil, nil
	})

	type testQueryInput struct {
		Language string `json:"language" jsonschema:"CxQL language name, e.g. Java or JavaScript"`
		Group    string `json:"group" jsonschema:"CxQL query group name"`
		Name     string `json:"name" jsonschema:"CxQL query name"`
		Code     string `json:"code" jsonschema:"Modified CxQL source code to test"`
	}
	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "test_query",
		Description: "Runs a modified version of a CxQL query without saving, creating a temporary project-level override if needed. Use this to iterate on query changes before saving.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, input testQueryInput) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.TestQuery(input.Language, input.Group, input.Name, input.Code)), nil, nil
	})

	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "save_query",
		Description: "Saves the last successfully tested CxQL query modification as a permanent override at the appropriate hierarchy level.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, input queryInput) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.SaveQuery(input.Language, input.Group, input.Name)), nil, nil
	})

	type searchInput struct {
		Substring string `json:"substring" jsonschema:"Text to search for within the scanned source code"`
	}
	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "search_code",
		Description: "Searches the scanned source code for a substring. Returns matching file paths and line numbers.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, input searchInput) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.SearchCode(input.Substring)), nil, nil
	})

	type showCodeInput struct {
		Path      string `json:"path" jsonschema:"File path within the scanned project"`
		LineStart int    `json:"line_start" jsonschema:"First line to show (1-indexed)"`
		LineEnd   int    `json:"line_end" jsonschema:"Last line to show (1-indexed)"`
	}
	mcpsdk.AddTool(m.server, &mcpsdk.Tool{
		Name:        "show_source_code",
		Description: "Returns source code from a specific file and line range, including any dataflow annotations.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, input showCodeInput) (*mcpsdk.CallToolResult, any, error) {
		return textResult(m.ShowSourceCode(input.Path, input.LineStart, input.LineEnd)), nil, nil
	})
}

func (m *MCP) Start() error {
	m.logger.Debug("Starting MCP server")
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	return m.server.Run(ctx, &mcpsdk.StdioTransport{})
}

func (m *MCP) Shutdown() {
	if m.cancel != nil {
		m.cancel()
	}
	m.backend.Shutdown()
}
