package mcp

import (
	"fmt"
)

// given a full path to a finding, eg: https://deu.ast.checkmarx.net/sast-results/9ee3602f-94c6-4230-8be4-bdb6d9fdeb03/8130f76b-c6dc-487e-a2a4-54be9f6a5945?resultId=Z6ZsAZogrxT9WY99pVuEDiLbbFA%3D&pagination=pageSize%3D10%3BcurrentPage%3D1&grouping=groups%255B0%255D%3Dlanguage%3Bgroups%255B1%255D%3Dseverity%3Bgroups%255B2%255D%3DqueryName
// get the query information (code, description, recommendation) for the finding plus the code snippets
func (m *MCP) CreateSessionFromURL(path string) string {
	err := m.backend.Initialize(path)
	if err != nil {
		return fmt.Sprintf("Error: Failed to initialize session data: %v", err)
	}

	err = m.backend.CreateAuditSession()
	if err != nil {
		return fmt.Sprintf("Error: Failed to create audit session: %v", err)
	}

	present, err := m.backend.CheckFindingStatus()
	if err != nil {
		return fmt.Sprintf("Error: Failed to check finding status: %v", err)
	}
	if !present {
		return fmt.Sprintf("Error: The session was created, but the scan in web-audit did not find this finding: %s", m.backend.Result.String())
	}

	return "The session was created successfully and the finding is present."
}

/*
returns the current state:
  - current finding details (description, recommendation),
  - code snippets with the dataflow path
  - the CxQL query that was used to find the issue
*/
func (m *MCP) GetCurrentState() string {
	result := ""
	result += m.GetFindingDetails() + "\n"
	result += m.GetCodeSnippets() + "\n"
	result += m.GetQueryInfo(m.backend.Result.Data.LanguageName, m.backend.Result.Data.Group, m.backend.Result.Data.QueryName)

	return result
}

// return the explanation of the finding eg: Missing_HSTS description + recommendation
func (m *MCP) GetFindingDetails() string {
	if m.backend.Result == nil {
		return "Error: No finding details available"
	}

	details, err := m.backend.GetQueryDescription(m.backend.Result.Data.QueryID)
	if err != nil {
		return fmt.Sprintf("Error: Failed to get finding details: %s", err)
	}
	return fmt.Sprintf("Finding %s.%s.%s details:\nDescription: %s\nRisk: %s\nRecommendation: %s", m.backend.Result.Data.LanguageName, m.backend.Result.Data.Group, m.backend.Result.Data.QueryName, details.ResultDescription, details.Risk, details.GeneralRecommendations)
}

// returns the source code involved in the finding or query dataflow
func (m *MCP) GetCodeSnippets() string {
	return m.backend.GetCodeSnippets()
}

// returns a list of files + lines matching the search string, eg /src/somefile.java:123 this is the line of code
func (m *MCP) SearchCode(substring string) string {
	return ""
}

// returns the source code along with any comments added by the MCP process (dataflow markers)
func (m *MCP) ShowSourceCode(path string, lineStart, lineEnd int) string {
	return ""
}

// returns the CxQL hierarchy + source code for a given query, eg: Missing_HSTS_Header
func (m *MCP) GetQueryInfo(language, group, name string) string {
	queries, err := m.backend.GetQueryHierarchy(language, group, name)
	if err != nil {
		return fmt.Sprintf("Error: Failed to get query hierarchy for %s.%s.%s: %s", language, group, name, err)
	}

	return m.backend.FormatQueryHierarchy(queries)
}

// checks i the original finding is found in the audit session or not
func (m *MCP) CheckOriginalFinding() string {
	present, err := m.backend.CheckFindingStatus()
	if err != nil {
		return fmt.Sprintf("Error: Failed to check finding status: %v", err)
	}
	if !present {
		return "Finding is not present"
	}
	return "Finding is present"
}

// runs an existing query and returns the results (which may be multiple dataflow paths)
func (m *MCP) RunQuery(language, group, query string) string {

	return ""
}

// runs an updated version of a CxQL query, without saving the changes, and returns the results (which may be multiple dataflow paths)
func (m *MCP) TestQuery(language, group, query, code string) string {

	return ""
}

// saves an updated version of a CxQL query based on the last successful RunQuery call.
func (m *MCP) SaveQuery(language, group, query string) string {

	return ""
}
