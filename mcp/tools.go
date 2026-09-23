package mcp

import (
	"fmt"

	"github.com/cxpsemea/Cx1ClientGo"
)

const (
	QUERY_LEVEL_PROJECT     = "Project"
	QUERY_LEVEL_APPLICATION = "Application"
	QUERY_LEVEL_TENANT      = "Tenant"
	QUERY_LEVEL_PRODUCT     = "Product"
)

// given a full path to a finding, eg: https://deu.ast.checkmarx.net/sast-results/9ee3602f-94c6-4230-8be4-bdb6d9fdeb03/8130f76b-c6dc-487e-a2a4-54be9f6a5945?resultId=Z6ZsAZogrxT9WY99pVuEDiLbbFA%3D&pagination=pageSize%3D10%3BcurrentPage%3D1&grouping=groups%255B0%255D%3Dlanguage%3Bgroups%255B1%255D%3Dseverity%3Bgroups%255B2%255D%3DqueryName
// get the query information (code, description, recommendation) for the finding plus the code snippets
// the tpFindings represent other projects with true-positive (and true-negative) findings of the same type
// those other projects will be cloned into a new testing application generated for this run
func (m *MCP) CreateSessionFromURL(targetFinding string, tpFindings, tnFindings []string) string {
	result, scan, err := m.backend.Initialize(targetFinding)
	if err != nil {
		return fmt.Sprintf("Error: Failed to initialize session data: %v", err)
	}

	err = m.backend.CreateTestEnvironment(result, scan, tpFindings, tnFindings)
	if err != nil {
		return fmt.Sprintf("Error: Failed to create test environment: %v", err)
	}

	summary, fails := m.backend.CheckControlProjects()
	if fails > 0 {
		return fmt.Sprintf("Error: %d control projects failed validation\n%s", fails, summary)
	}

	err = m.backend.CreateAuditSession()
	if err != nil {
		return fmt.Sprintf("Error: Failed to create audit session: %v\n%s", err, summary)
	}

	present, err := m.backend.CheckFindingStatus()
	if err != nil {
		return fmt.Sprintf("Error: Failed to check finding status: %v\n%s", err, summary)
	}
	if !present {
		return fmt.Sprintf("Error: The session was created, but the scan in web-audit did not find this finding: %s\n%s", m.backend.Target.Result.String(), summary)
	}

	return "The session was created successfully and the finding is present."
}

// returns the current state:
//   - current finding details (description, recommendation),
//   - code snippets with the dataflow path
//   - the CxQL query that was used to find the issue
func (m *MCP) GetCurrentState() string {
	result := ""
	result += m.GetFindingDetails() + "\n"
	result += m.GetCodeSnippets() + "\n"
	result += m.GetQueryInfo(m.backend.Target.Result.Data.LanguageName, m.backend.Target.Result.Data.Group, m.backend.Target.Result.Data.QueryName)

	return result
}

// return the explanation of the finding eg: Missing_HSTS description + recommendation
func (m *MCP) GetFindingDetails() string {
	if m.backend.Target.Result == nil {
		return "Error: No finding details available"
	}

	details, err := m.backend.GetQueryDescription(m.backend.Target.Result.Data.QueryID)
	if err != nil {
		return fmt.Sprintf("Error: Failed to get finding details: %s", err)
	}
	return fmt.Sprintf("A false-positive finding %s.%s.%s was found in the source code.\nDescription: %s\nRisk: %s\nRecommendation: %s", m.backend.Target.Result.Data.LanguageName, m.backend.Target.Result.Data.Group, m.backend.Target.Result.Data.QueryName, details.ResultDescription, details.Risk, details.GeneralRecommendations)
}

// returns the source code involved in the finding or query dataflow
func (m *MCP) GetCodeSnippets() string {
	return m.backend.GetCodeSnippets()
}

// returns a list of files + lines matching the search string, eg /src/somefile.java:123 this is the line of code
func (m *MCP) SearchCode(substring string) string {
	return ""
}

// return the high-level description of the process
func (m *MCP) GetHLD() string {
	return m.HLD
}

// returns the source code along with any comments added by the MCP process (dataflow markers)
func (m *MCP) ShowSourceCode(path string, lineStart, lineEnd int) string {

	return ""
}

// returns the CxQL hierarchy + source code for a given query, eg: Missing_HSTS_Header
func (m *MCP) GetQueryInfo(language, group, name string) string {
	return m.GetQueryInfoFiltered(language, group, name, []bool{true, true, true, true}, []bool{true, true, true, true})
}

// returns the CxQL hierarchy + source code for a given query, eg: Missing_HSTS_Header
func (m *MCP) GetQueryInfoFiltered(language, group, name string, view, edit []bool) string {

	queries, err := m.backend.GetQueryHierarchy(language, group, name)
	if err != nil {
		return fmt.Sprintf("Error: Failed to get query info for %s.%s.%s: %s", language, group, name, err)
	}

	return m.backend.FormatQueryHierarchy(queries, view, edit)
}

// returns only the source code for a query at a specific hierarchy level, eg: Missing_HSTS_Header at the Project level
func (m *MCP) GetQueryCode(level, language, group, query string) string {
	level, levelID := m.getLevels(level)
	language = m.backend.QueryLanguageCheck(language, group, query)

	targetQuery := m.backend.Queries.GetQueryByLevelAndName(level, levelID, language, group, query)
	if targetQuery == nil {
		return "Query doesn't exist"
	}

	source, err := m.backend.GetQuerySource(targetQuery)
	if err != nil {
		return fmt.Sprintf("Error: Failed to retrieve the query's source code: %s", err)
	}

	return fmt.Sprintf("```csharp\n%s\n```\n", source)
}

// checks if the original finding is found in the audit session or not
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

// checks if the in-scope finding is present in each control project (TP projects
// should find it, TN projects should not), based on each control project's most
// recent scan.
func (m *MCP) CheckControlProjects() string {
	summary, fails := m.backend.CheckControlProjects()
	if fails > 0 {
		return fmt.Sprintf("Regression: %d control projects failed validation.\n%s", fails, summary)
	}
	return fmt.Sprintf("All control projects passed validation.\n%s", summary)
}

// re-scans every control project (using the currently active query overrides)
// and then re-validates them, so a query edit can be checked against the TP/TN
// control projects without re-checking the original finding.
func (m *MCP) ScanControlProjects() string {
	if err := m.backend.ScanControlProjects(); err != nil {
		return fmt.Sprintf("Error: Failed to scan control projects: %v", err)
	}
	return ""
}

// runs an existing query and returns the results (which may be multiple dataflow paths)
func (m *MCP) RunQuery(level, language, group, query string) string {
	level, levelID := m.getLevels(level)
	language = m.backend.QueryLanguageCheck(language, group, query)
	executedQuery := m.backend.Queries.GetQueryByLevelAndName(level, levelID, language, group, query)
	if executedQuery == nil {
		return fmt.Sprintf("Error: The %s-level query %s.%s.%s does not exist", level, language, group, query)
	}

	_, err := m.backend.GetQuerySource(executedQuery)
	if err != nil {
		return "Error: Failed to retrieve the query's current source code"
	}

	results, err := m.backend.RunQuery(executedQuery, executedQuery.Source)
	if err != nil {
		return fmt.Sprintf("Error: Failed to run the query in the audit session: %s", err)
	}

	return m.backend.ProcessAuditResults(executedQuery, &results, executedQuery.Source)
}

// runs an updated version of a CxQL query, without saving the changes, and returns the results (which may be multiple dataflow paths)
func (m *MCP) TestQuery(level, language, group, query, code string) string {
	level, _ = m.getLevels(level)
	language = m.backend.QueryLanguageCheck(language, group, query)
	if language == "Common" {
		return fmt.Sprintf("Error: Cannot change Common-language query %s.%s", group, query)
	}

	executedQuery, err := m.getTargetQuery(level, language, group, query, code)
	if err != nil {
		return fmt.Sprintf("Error: %s", err)
	}

	results, err := m.backend.RunQuery(executedQuery, code)
	if err != nil {
		return fmt.Sprintf("Error: Failed to run the query in the audit session: %s", err)
	}

	return m.backend.ProcessAuditResults(executedQuery, &results, code)
}

// saves an updated version of a CxQL query based on the last successful RunQuery call.
func (m *MCP) SaveQuery(level, language, group, query, code string) string {
	level, _ = m.getLevels(level)
	language = m.backend.QueryLanguageCheck(language, group, query)
	if language == "Common" {
		return fmt.Sprintf("Error: Cannot change Common-language query %s.%s", group, query)
	}
	executedQuery, err := m.getTargetQuery(level, language, group, query, code)
	if err != nil {
		return fmt.Sprintf("Error: %s", err)
	}

	if code != executedQuery.Source {
		results, err := m.backend.SaveQuery(executedQuery, code)
		if err != nil {
			return fmt.Sprintf("Error: Failed to run the query in the audit session: %s", err)
		}

		if len(results.FailedQueries) > 0 {
			return m.backend.ProcessRunFailures(executedQuery, &results, code)
		}
	}
	if resp := m.ScanControlProjects(); resp != "" {
		return fmt.Sprintf("Error: failed to scan control projects after query update. %s", resp)
	}
	return fmt.Sprintf("Query %s.%s.%s saved.", language, group, query)
}

// reverts a query override to the version it had before the first save_query call
// touched it in this session. Errors if the query was never saved.
func (m *MCP) RestoreQuery(level, language, group, query string) string {
	levelStr, levelID := m.getLevels(level)
	language = m.backend.QueryLanguageCheck(language, group, query)
	if language == "Common" {
		return fmt.Sprintf("Error: Cannot change Common-language query %s.%s", group, query)
	}

	executedQuery := m.backend.Queries.GetQueryByLevelAndName(levelStr, levelID, language, group, query)
	if executedQuery == nil {
		return fmt.Sprintf("Error: The %s-level query %s.%s.%s does not exist", level, language, group, query)
	}

	results, original, err := m.backend.RestoreQuery(executedQuery)
	if err != nil {
		return fmt.Sprintf("Error: %s", err)
	}

	if len(results.FailedQueries) > 0 {
		return m.backend.ProcessRunFailures(executedQuery, &results, original)
	}

	if resp := m.ScanControlProjects(); resp != "" {
		return fmt.Sprintf("Error: failed to scan control projects after query restore. %s", resp)
	}
	return fmt.Sprintf("Query %s.%s.%s restored to its original version.", language, group, query)
}

func (m *MCP) GetCurrentApplicationID() string {
	return m.backend.GetCurrentApplicationID()
}

func (m *MCP) GetCurrentProjectID() string {
	return m.backend.GetCurrentProjectID()
}

func (m *MCP) getLevels(level string) (string, string) {
	switch level {
	case QUERY_LEVEL_APPLICATION:
		return m.backend.Cx1Client.QueryTypeApplication(), m.backend.GetCurrentApplicationID()
	case QUERY_LEVEL_TENANT:
		return m.backend.Cx1Client.QueryTypeTenant(), m.backend.Cx1Client.QueryTypeTenant()
	case QUERY_LEVEL_PRODUCT:
		return m.backend.Cx1Client.QueryTypeProduct(), m.backend.Cx1Client.QueryTypeProduct()
	default:
		return m.backend.Cx1Client.QueryTypeProject(), m.backend.GetCurrentProjectID()
	}
}

func (m *MCP) getTargetQuery(level, language, group, query, code string) (*Cx1ClientGo.SASTQuery, error) {
	levelStr, levelID := m.getLevels(level)
	executedQuery := m.backend.Queries.GetQueryByLevelAndName(levelStr, levelID, language, group, query)
	if executedQuery == nil {
		baseQuery := m.backend.Queries.GetClosestQueryByLevelAndName(levelStr, levelID, language, group, query)
		if baseQuery == nil {
			// create query
			b := false
			src := "result = All.NewCxList();"
			if level == QUERY_LEVEL_TENANT {
				src = code
			}
			q, err := m.backend.CreateNewQuery(Cx1ClientGo.SASTQuery{
				Source:             src,
				Language:           language,
				Group:              group,
				Name:               query,
				Severity:           "Info",
				CweID:              0,
				IsExecutable:       &b,
				QueryDescriptionId: 0,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create new tenant-level query %s.%s.%s: %s", language, group, query, err)
			}
			baseQuery = q
		}

		if level == QUERY_LEVEL_TENANT {
			executedQuery = baseQuery
		} else {
			q, err := m.backend.CreateOverride(levelStr, levelID, baseQuery)
			if err != nil {
				return nil, fmt.Errorf("failed to create %s-level query override for query %s.%s.%s: %s", levelStr, language, group, query, err)
			}
			executedQuery = q
		}
	}
	return executedQuery, nil
}
