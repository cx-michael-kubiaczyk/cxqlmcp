package mcp

import (
	"fmt"
)

// given a full path to a finding, eg: https://deu.ast.checkmarx.net/sast-results/9ee3602f-94c6-4230-8be4-bdb6d9fdeb03/8130f76b-c6dc-487e-a2a4-54be9f6a5945?resultId=Z6ZsAZogrxT9WY99pVuEDiLbbFA%3D&pagination=pageSize%3D10%3BcurrentPage%3D1&grouping=groups%255B0%255D%3Dlanguage%3Bgroups%255B1%255D%3Dseverity%3Bgroups%255B2%255D%3DqueryName
// get the query information (code, description, recommendation) for the finding plus the code snippets
func (m *MCP) CreateSessionFromURL(path string) (string, error) {
	err := m.backend.Initialize(path)
	if err != nil {
		return "", fmt.Errorf("failed to initialize session data: %v", err)
	}

	err = m.backend.CreateAuditSession()
	if err != nil {
		return "", fmt.Errorf("failed to create audit session: %v", err)
	}

	present, err := m.backend.CheckFindingStatus()
	if err != nil {
		return "", fmt.Errorf("failed to check finding status: %v", err)
	}
	if !present {
		return "", fmt.Errorf("The scan in web-audit did not find this finding: %s", m.backend.Result.String())
	}

	//m.logger.Infof("Finding %s is present: %s", m.backend.Result.String(), m.Vuln.String())

	return "The session was created successfully and the finding is present", nil
}

/*
returns the current state:
  - current finding details (description, recommendation),
  - code snippets with the dataflow path
  - the CxQL query that was used to find the issue
*/
func (m *MCP) GetCurrentState() (string, error) {

	return "", nil
}

// return the explanation of the finding eg: Missing_HSTS description + recommendation
func (m *MCP) GetFindingDetails(language, group, name string) (string, error) {

	return "", nil
}

// returns the source code involved in the finding or query dataflow
func (m *MCP) GetCodeSnippets() (string, error) {

	return "", nil
}

// returns a list of files + lines matching the search string, eg /src/somefile.java:123 this is the line of code
func (m *MCP) SearchCode(substring string) (string, error) {
	return "", nil
}

// returns the source code along with any comments added by the MCP process (dataflow markers)
func (m *MCP) ShowSourceCode(path string, lineStart, lineEnd int) (string, error) {
	return "", nil
}

// returns the CxQL hierarchy + source code for a given query, eg: Missing_HSTS_Header
func (m *MCP) GetQueryInfo(language, group, name string) (string, error) {
	queries, err := m.backend.GetQueryHierarchy(language, group, name)
	if err != nil {
		return "", err
	}

	return m.backend.FormatQueryHierarchy(queries), nil
}

// checks i the original finding is found in the audit session or not
func (m *MCP) CheckOriginalFinding() (string, error) {
	present, err := m.backend.CheckFindingStatus()
	if err != nil {
		return "", fmt.Errorf("failed to check finding status: %v", err)
	}
	if !present {
		return "Finding is not present", nil
	}
	return "Finding is present", nil
}

// runs an updated version of a CxQL query, without saving the changes, and returns the results (which may be multiple dataflow paths)
func RunQuery(language, group, query, code string) (string, error) {

	return "", nil
}

// saves an updated version of a CxQL query based on the last successful RunQuery call.
func SaveQuery(language, group, query string) error {

	return nil
}
