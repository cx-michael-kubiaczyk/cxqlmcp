package mcp

import (
	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/cxpsemea/cxqlmcp/mcp/backend"
	"github.com/sirupsen/logrus"
)

type MCP struct {
	backend backend.MCPBackend
	logger  *logrus.Logger
	HLD     string // high-level description of the query process
}

func NewMCP(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) *MCP {
	return &MCP{
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
}

func (m *MCP) Start() error {
	m.logger.Debug("Starting MCP server")
	return nil
}

func (m *MCP) Shutdown() {
	m.backend.Shutdown()
}
