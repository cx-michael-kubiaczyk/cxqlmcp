package mcp

import (
	"fmt"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/cxpsemea/cxqlmcp/mcp/backend"
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

// returns the current state:
//   - current finding details (description, recommendation),
//   - code snippets with the dataflow path
//   - the CxQL query that was used to find the issue
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
	return fmt.Sprintf("A false-positive finding %s.%s.%s was found in the source code.\nDescription: %s\nRisk: %s\nRecommendation: %s", m.backend.Result.Data.LanguageName, m.backend.Result.Data.Group, m.backend.Result.Data.QueryName, details.ResultDescription, details.Risk, details.GeneralRecommendations)
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
	queries, err := m.backend.GetQueryHierarchy(language, group, name)
	if err != nil {
		return fmt.Sprintf("Error: Failed to get query hierarchy for %s.%s.%s: %s", language, group, name, err)
	}

	return m.backend.FormatQueryHierarchy(queries)
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

// runs an existing query and returns the results (which may be multiple dataflow paths)
func (m *MCP) RunQuery(language, group, query string) string {
	executedQuery := m.backend.Queries.GetClosestQueryByLevelAndName(m.backend.Cx1Client.QueryTypeProject(), m.backend.Result.ProjectID, language, group, query)
	if executedQuery == nil {
		return "Error: The query %s.%s.%s does not exist"
	}

	_, err := m.backend.GetQuerySource(executedQuery)
	if err != nil {
		return "Error: Failed to retrieve the query's current source code"
	}

	results, err := m.backend.RunQuery(executedQuery, executedQuery.Source)
	if err != nil {
		return fmt.Sprintf("Error: Failed to run the query in the audit session: %s", err)
	}

	return m.processAuditResults(executedQuery, &results)
}

// runs an updated version of a CxQL query, without saving the changes, and returns the results (which may be multiple dataflow paths)
func (m *MCP) TestQuery(language, group, query, code string) string {
	executedQuery := m.backend.Queries.GetClosestQueryByLevelAndName(m.backend.Cx1Client.QueryTypeProject(), m.backend.Result.ProjectID, language, group, query)
	if executedQuery == nil {
		return "Error: The query %s.%s.%s does not exist"
	}
	if executedQuery.Level != m.backend.Cx1Client.QueryTypeProject() {
		q, err := m.backend.CreateOverride(executedQuery)
		if err != nil {
			return fmt.Sprintf("Error: Failed to create Project-level query override for query %s.%s.%s: %s", language, group, query, err)
		}
		executedQuery = q
	}

	results, err := m.backend.RunQuery(executedQuery, code)
	if err != nil {
		return fmt.Sprintf("Error: Failed to run the query in the audit session: %s", err)
	}

	return m.processAuditResults(executedQuery, &results)
}

// saves an updated version of a CxQL query based on the last successful RunQuery call.
func (m *MCP) SaveQuery(language, group, query string) string {

	return ""
}

func (m *MCP) processAuditResults(executedQuery *Cx1ClientGo.SASTQuery, results *Cx1ClientGo.QueryRun) string {
	response := strings.Builder{}

	if len(results.FailedQueries) > 0 {
		//cs := backend.NewCodeSet()
		for _, f := range results.FailedQueries {
			q, err := m.backend.UpdateQueryByKey(f.QueryID)
			if err != nil {
				fmt.Fprintf(&response, "Error: Failed to retrieve query with key %s: %s", f.QueryID, err)
				response.WriteString("\n")
			}
			var fs backend.FileSource
			if q.EditorKey == executedQuery.EditorKey {
				fs = backend.NewFileSource(m.backend.TempCode)
			} else {
				fs = backend.NewFileSource(q.Source)
			}
			if q != nil {
				m.logger.Debugf("Query %s.%s.%s had the following errors: %+v", q.Language, q.Group, q.Name, f.Errors)
				for _, e := range f.Errors {
					fs.Augment("audit", "Error: "+e.Message, e.Line)
				}

				fmt.Fprintf(&response, "Error: The query %s.%s.%s ran with errors, shown inline in the code below.", q.Language, q.Group, q.Name)
				response.WriteString("\n")
				response.WriteString(fs.Code())
			} else {
				fmt.Fprintf(&response, "Error: Audit run result has unknown query with ID %s throwing errors.", f.QueryID)
				response.WriteString("\n")
			}
		}
	}

	if len(results.Results) > 0 {
		for _, r := range results.Results {
			vulns, err := m.backend.GetRunResults(r)
			if err != nil {
				fmt.Fprintf(&response, "Failed to get run result %s: %s", r.RunID, err)
				response.WriteString("\n")
			} else {
				parts := strings.Split(r.Title, " ")
				if len(parts) >= 1 {
					queryName := parts[0]
					var runQuery *Cx1ClientGo.SASTQuery
					if strings.EqualFold(queryName, executedQuery.Name) {
						runQuery = executedQuery
					} else {
						productQuery := m.backend.Queries.FindQuery(m.backend.Cx1Client.QueryTypeProduct(), "", executedQuery.Language, queryName, 0)
						if productQuery != nil {
							runQuery = productQuery
						} else {
							tenantQuery := m.backend.Queries.FindQuery(m.backend.Cx1Client.QueryTypeTenant(), "", executedQuery.Language, queryName, 0)
							if tenantQuery != nil {
								runQuery = tenantQuery
							} else {
								m.logger.Errorf("Failed to find %s query %s", executedQuery.Language, queryName)
							}
						}
					}

					if runQuery != nil {
						queryName = runQuery.Name
					} else {
						queryName = "Unknown query " + queryName
					}

					fmt.Fprintf(&response, "Query %s.%s.%s ran with %d results.", runQuery.Language, runQuery.Group, runQuery.Name, len(vulns))
					response.WriteString("\n")
					for i, v := range vulns {
						//fmt.Fprintf(&response, "%d: %+v", i, v)
						//response.WriteString("\n")
						if err := m.backend.VulnAugment(i, queryName, v); err != nil {
							m.logger.Errorf("Failed to augment code with %s vuln %s", queryName, v)
						}
					}
				} else {
					m.logger.Infof("Failed to get query from title: %s", r.Title)
				}
			}
		}

		response.WriteString("\nSource code:\n")
		response.WriteString(m.GetCodeSnippets())
	}

	return response.String()
}
