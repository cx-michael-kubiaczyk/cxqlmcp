package backend

import (
	"fmt"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

type MCPBackend struct {
	Cx1Client *Cx1ClientGo.Cx1Client
	Target    struct {
		Project     *Cx1ClientGo.Project
		Application *Cx1ClientGo.Application
		Result      *Cx1ClientGo.ScanSASTResult
		Scan        *Cx1ClientGo.Scan
		TestAppGUID string
		Query       []*Cx1ClientGo.SASTQuery
		QueryID     uint64
	}
	ControlProjects []ControlProject

	Vuln    *Cx1ClientGo.QueryVulnerability
	session *Cx1ClientGo.AuditSession

	logger       *logrus.Logger
	ScanSources  CodeSet
	Queries      Cx1ClientGo.SASTQueryCollection
	descriptions map[uint64]Cx1ClientGo.SASTQueryDescription
}

// ControlProject represents a TP/TN reference project cloned into the test
// application for a create_session run, for later use by CheckControlProjects.
type ControlProject struct {
	Label           string // "TP" or "TN"
	Index           int    // 1-based position within its label group
	ProjectID       string
	ProjectName     string
	ScanID          string
	SourceProjectID string // original project this was cloned from
	SourceScanID    string // original scan this was cloned from
	ScanStatus      string // final polled status, or "failed: <err>" if scan/upload/create failed
}

func NewBackend(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) MCPBackend {
	return MCPBackend{Cx1Client: cx1client,
		logger:       logger,
		ScanSources:  NewCodeSet(),
		descriptions: make(map[uint64]Cx1ClientGo.SASTQueryDescription),
	}
}

func (m *MCPBackend) Initialize(path string) (*Cx1ClientGo.ScanSASTResult, *Cx1ClientGo.Scan, error) {
	m.logger.Debug("Getting query collection")
	qc, err := m.Cx1Client.GetSASTQueryCollection()
	if err != nil {
		return nil, nil, err
	}
	m.Queries = qc

	_, sid, rid, err := extractIDFromURL(path)
	if err != nil {
		return nil, nil, err
	}

	scan, err := m.Cx1Client.GetScanByID(sid)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get scan: %v", err)
	}

	filter := Cx1ClientGo.ScanSASTResultsFilter{
		BaseFilter: Cx1ClientGo.BaseFilter{Limit: 10},
		ScanID:     sid,
		ResultIDs:  []string{rid},
	}

	_, results, err := m.Cx1Client.GetAllScanSASTResultsFiltered(filter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get results: %v", err)
	}

	if len(results) != 1 {
		return nil, nil, fmt.Errorf("expected 1 result, got %d", len(results))
	}

	m.Target.QueryID = results[0].Data.QueryID

	return &results[0], &scan, nil
}

func (m *MCPBackend) GetCurrentProjectID() string {
	if m.Target.Project == nil {
		return "Error: no project configured"
	}
	return m.Target.Project.ProjectID
}
func (m *MCPBackend) GetCurrentApplicationID() string {
	if m.Target.Application == nil {
		return "Error: no application configured"
	}
	return m.Target.Application.ApplicationID
}

// CreateTestEnvironment builds a disposable Cx1 Application containing a full-source
// copy of the current target project/scan (m.project/m.scan, populated by a prior
// call to Initialize), plus one control project per tpFindings/tnFindings entry.
// All projects share one preset containing only the target finding's query.
// On success, m.project/m.application/m.scan are reassigned to the new target
// project/app/scan so subsequent audit-session calls operate on the copy.
// Returns a human-readable per-project summary, and an error only if the target
// project/scan itself failed (TP/TN failures are reported in the summary only).
func (m *MCPBackend) CreateTestEnvironment(result *Cx1ClientGo.ScanSASTResult, scan *Cx1ClientGo.Scan, tpFindings, tnFindings []string) error {
	if scan == nil || result == nil {
		return fmt.Errorf("no target project/scan loaded")
	}

	guid, err := newShortID(10)
	if err != nil {
		return fmt.Errorf("failed to generate test id: %v", err)
	}
	m.Target.TestAppGUID = guid

	app, err := m.Cx1Client.CreateApplication("CxQL-" + guid)
	if err != nil {
		return fmt.Errorf("failed to create test application: %v", err)
	}
	m.Target.Application = &app

	if _, err := m.configureCustomPreset(); err != nil {
		return fmt.Errorf("failed to configure preset: %v", err)
	}

	specs := []projectSpec{
		{
			label:           "Target",
			index:           0,
			projectName:     "CxQL-Target-" + guid,
			sourceProjectID: scan.ProjectID,
			sourceScanID:    scan.ScanID,
		},
	}

	appendSpecs := func(label string, urls []string) error {
		for i, u := range urls {
			pid, sid, _, err := extractIDFromURL(u)
			if err != nil {
				return fmt.Errorf("failed to parse %s url %q: %v", label, u, err)
			}
			specs = append(specs, projectSpec{
				label:           label,
				index:           i + 1,
				projectName:     fmt.Sprintf("CxQL-%s-%d-%s", label, i+1, guid),
				sourceProjectID: pid,
				sourceScanID:    sid,
			})
		}
		return nil
	}
	if err := appendSpecs("TP", tpFindings); err != nil {
		return err
	}
	for i, sid := range tnFindings {
		scan, err := m.Cx1Client.GetScanByID(sid)
		if err != nil {
			return fmt.Errorf("failed to get TN source scan %s: %v", sid, err)
		}

		specs = append(specs, projectSpec{
			label:           "TN",
			index:           i + 1,
			projectName:     fmt.Sprintf("CxQL-%s-%d-%s", "TN", i+1, guid),
			sourceProjectID: scan.ProjectID,
			sourceScanID:    sid,
		})
	}

	// First pass: trigger every project's scan without waiting.
	scans := make([]specResult, len(specs))
	for i, spec := range specs {
		m.logger.Debugf("Processing %s %d: source scan ID %s", spec.label, spec.index, spec.sourceScanID)
		sourceZip, err := m.getScanSourceZip(spec.sourceScanID)
		if err != nil {
			scans[i] = specResult{spec: spec, err: fmt.Errorf("failed to fetch source: %v", err)}
			continue
		}
		project, err := m.createProject(app.ApplicationID, spec.projectName, "CxQL-"+m.Target.TestAppGUID)
		if err != nil {
			scans[i] = specResult{spec: spec, err: err}
			continue
		}
		scan, err := m.scanProject(project.ProjectID, sourceZip, "test")
		scans[i] = specResult{spec: spec, project: &project, scan: &scan, err: err}
	}

	// Second pass: poll every scan that was triggered successfully.
	for i := range scans {
		if scans[i].err != nil {
			continue
		}
		polled, err := m.Cx1Client.ScanPollingDetailed(scans[i].scan)
		if err != nil {
			scans[i].err = fmt.Errorf("scan polling failed: %v", err)
			continue
		}
		scans[i].scan = &polled
	}

	var targetErr error
	for _, r := range scans {
		if r.err != nil {
			if r.spec.label == "Target" {
				targetErr = r.err
			} else {
				m.ControlProjects = append(m.ControlProjects, ControlProject{
					Label:           r.spec.label,
					Index:           r.spec.index,
					SourceProjectID: r.spec.sourceProjectID,
					SourceScanID:    r.spec.sourceScanID,
					ScanStatus:      "failed: " + r.err.Error(),
				})
			}
			continue
		}

		if r.spec.label == "Target" {
			m.Target.Project = r.project
			m.Target.Scan = r.scan
		} else {
			m.ControlProjects = append(m.ControlProjects, ControlProject{
				Label:           r.spec.label,
				Index:           r.spec.index,
				ProjectID:       r.project.ProjectID,
				ProjectName:     r.spec.projectName,
				ScanID:          r.scan.ScanID,
				SourceProjectID: r.spec.sourceProjectID,
				SourceScanID:    r.spec.sourceScanID,
				ScanStatus:      r.scan.Status,
			})
		}
	}

	if targetErr != nil {
		return fmt.Errorf("failed to create target project: %v", targetErr)
	}

	if scans[0].err != nil {
		return fmt.Errorf("target FP repro scan failed: %s", scans[0].err)
	}

	scanresults, err := m.Cx1Client.GetAllScanSASTResultsByID(scans[0].scan.ScanID)
	if err != nil {
		return fmt.Errorf("failed to get scan results for target repro scan %s: %s", scans[0].scan.ScanID, err)
	}

	for _, r := range scanresults {
		if r.SimilarityID == result.SimilarityID && r.Data.QueryID == result.Data.QueryID {
			m.Target.Result = &r
			break
		}
	}
	if m.Target.Result == nil {
		return fmt.Errorf("did not find the expected similarityID %s & queryID %s in the new target repro scan %s", result.SimilarityID, result.Data.QueryName, scans[0].scan.String())
	}

	return nil
}

func (m *MCPBackend) Shutdown() {
	if m.session != nil {
		m.endSession()
	}
}

func (m *MCPBackend) CreateAuditSession() error {
	if m.session != nil {
		m.endSession()
	}
	session, err := m.Cx1Client.GetAuditSessionByID("sast", m.Target.Project.ProjectID, m.Target.Scan.ScanID)
	if err != nil {
		return fmt.Errorf("failed to get audit session: %v", err)
	}
	m.session = &session

	if err = m.UpdateQueryCollection(); err != nil {
		return err
	}

	query := m.Queries.GetQueryByID(m.Target.Result.Data.QueryID)
	if query == nil {
		return fmt.Errorf("failed to find query with ID %d", m.Target.Result.Data.QueryID)
	}
	m.logger.Debugf("Finding is from query %s", query.String())

	m.Target.Query, err = m.GetQueryHierarchy(query.Language, query.Group, query.Name)
	if err != nil {
		return fmt.Errorf("failed to get query hierarchy: %v", err)
	}

	return nil
}

func (m *MCPBackend) CheckFindingStatus() (bool, error) {
	m.Vuln = nil
	result, err := m.RunQuery(m.closestQuery(), m.closestQuery().Source)
	if err != nil {
		return false, fmt.Errorf("failed to run query: %v", err)
	}

	m.logger.Debugf("Looking for finding: %+v", m.Target.Result)
	for _, r := range result.Results {
		vulns, err := m.GetRunResults(r)
		if err != nil {
			return false, fmt.Errorf("Error getting results: %s", err)
		} else {
			for _, v := range vulns {
				if findingsEqual(m.Target.Result, v) {
					m.Vuln = &v
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (m *MCPBackend) CheckControlProjects() (string, int) {
	fails := 0
	summary := strings.Builder{}
	for _, cp := range m.ControlProjects {
		state := ""
		findingStatus, err := m.checkControlFindingStatus(cp.ScanID)
		if err != nil {
			state = "Error: " + err.Error()
			fails++
		} else if findingStatus {
			if cp.Label == "TP" {
				state = "OK"
			} else {
				state = "NOK"
				fails++
			}
		} else {
			if cp.Label == "TN" {
				state = "OK"
			} else {
				state = "NOK"
				fails++
			}
		}

		fmt.Fprintf(&summary, "%s-%d: %s\n", cp.Label, cp.Index, state)
	}

	return summary.String(), fails
}

// ScanControlProjects re-scans every control project using its cached source zip,
// against whatever query overrides are currently in effect. Call this after saving
// a query change, then call CheckControlProjects to re-validate TP/TN status
// against the fresh scans. Per-project failures are recorded on that project's
// ScanStatus and do not abort the others; only a fatal error (no control projects
// configured) is returned.
func (m *MCPBackend) ScanControlProjects() error {
	if len(m.ControlProjects) == 0 {
		return fmt.Errorf("no control projects configured for this session")
	}

	scans := make([]Cx1ClientGo.Scan, len(m.ControlProjects))
	for i, cp := range m.ControlProjects {
		if cp.ProjectID == "" {
			continue // failed during CreateTestEnvironment; nothing to rescan
		}
		sourceZip, err := m.getScanSourceZip(cp.SourceScanID)
		if err != nil {
			m.ControlProjects[i].ScanStatus = "failed: " + err.Error()
			continue
		}
		scan, err := m.scanProject(cp.ProjectID, sourceZip, "test")
		if err != nil {
			m.ControlProjects[i].ScanStatus = "failed: " + err.Error()
			continue
		}
		scans[i] = scan
	}

	for i := range scans {
		if m.ControlProjects[i].ProjectID == "" || scans[i].ScanID == "" {
			continue
		}
		polled, err := m.Cx1Client.ScanPollingDetailed(&scans[i])
		if err != nil {
			m.ControlProjects[i].ScanStatus = "failed: scan polling: " + err.Error()
			continue
		}
		m.ControlProjects[i].ScanID = polled.ScanID
		m.ControlProjects[i].ScanStatus = polled.Status
	}

	return nil
}

func (m *MCPBackend) GetRunResults(result Cx1ClientGo.QueryRunResult) ([]Cx1ClientGo.QueryVulnerability, error) {
	var vulns []Cx1ClientGo.QueryVulnerability

	vulnerabilities, err := m.Cx1Client.GetQueryRunResultsByID(m.session, result.RunID)
	if err != nil {
		return vulns, fmt.Errorf("Error getting results: %s", err)
	} else {
		for _, v := range vulnerabilities {
			vuln, err := m.Cx1Client.GetQueryRunVulnerabilityByID(m.session, result.RunID, v.VulnerabilityID)
			if err != nil {
				return vulns, fmt.Errorf("Error getting vulnerability: %s", err)
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}

func (m *MCPBackend) GetQuerySource(query *Cx1ClientGo.SASTQuery) (string, error) {
	q, err := m.Cx1Client.GetAuditSASTQueryByKey(m.session, query.EditorKey)
	if err != nil {
		return "", fmt.Errorf("failed to get query source: %v", err)
	}
	query.MergeQuery(q)
	query.Source = q.Source
	m.Queries.AddQuery(*query)
	return q.Source, nil
}

func (m *MCPBackend) RunQuery(query *Cx1ClientGo.SASTQuery, source string) (Cx1ClientGo.QueryRun, error) {
	if query == nil {
		return Cx1ClientGo.QueryRun{}, fmt.Errorf("nil query provided")
	}
	err := m.sessionRefresh()
	if err != nil {
		return Cx1ClientGo.QueryRun{}, fmt.Errorf("failed to refresh audit session: %v", err)
	}
	return m.Cx1Client.RunSASTQuery(m.session, query, source)
}

func (m *MCPBackend) SaveQuery(query *Cx1ClientGo.SASTQuery, source string) (Cx1ClientGo.QueryRun, error) {
	if query == nil {
		return Cx1ClientGo.QueryRun{}, fmt.Errorf("nil query provided")
	}
	err := m.sessionRefresh()
	if err != nil {
		return Cx1ClientGo.QueryRun{}, fmt.Errorf("failed to refresh audit session: %v", err)
	}

	_, run, err := m.Cx1Client.UpdateSASTQuerySource(m.session, *query, source)

	return Cx1ClientGo.QueryRun{FailedQueries: run}, err
}

func (m *MCPBackend) GetQueryDescription(queryId uint64) (Cx1ClientGo.SASTQueryDescription, error) {
	if desc, ok := m.descriptions[queryId]; ok {
		return desc, nil
	}

	description, err := m.Cx1Client.GetSASTQueryDescription(queryId)
	if err != nil {
		return Cx1ClientGo.SASTQueryDescription{}, fmt.Errorf("failed to get query description: %v", err)
	}

	m.descriptions[queryId] = description
	return description, nil
}

func (m MCPBackend) GetCodeSnippets() string {
	return m.ScanSources.GetSources()
}

func (m *MCPBackend) VulnAugment(number int, query string, vuln Cx1ClientGo.QueryVulnerability) error {
	for i, v := range vuln.Nodes {
		if !m.ScanSources.HasFile(v.FileID) {
			fileSource, err := m.Cx1Client.GetScannedFileSourceByID(m.Target.Scan.ScanID, v.FileID)
			if err != nil {
				return fmt.Errorf("failed to get file source: %v", err)
			}
			m.ScanSources.AddFile(v.FileID, fileSource)
		}
		m.ScanSources.AugmentFile(v.FileID, v.Line, AugSrc_Audit(fmt.Sprintf("%s #%d", query, number)), fmt.Sprintf("step %d: '%s'", i+1, vuln.Nodes[0].Name))
	}
	return nil
}

func (m *MCPBackend) UpdateQueryByKey(editorKey string) (*Cx1ClientGo.SASTQuery, error) {
	q, err := m.Cx1Client.GetAuditSASTQueryByKey(m.session, editorKey)
	if err != nil {
		return nil, err
	}
	m.Queries.UpdateNewQuery(&q)
	m.Queries.AddQuery(q)
	return m.Queries.GetQueryByEditorKey(editorKey), nil
}

func (m *MCPBackend) CreateOverride(level, levelID string, query *Cx1ClientGo.SASTQuery) (*Cx1ClientGo.SASTQuery, error) {
	m.sessionRefresh()
	_, err := m.Cx1Client.CreateSASTQueryOverride(m.session, level, query)
	if err != nil {
		return nil, err
	}

	err = m.UpdateQueryCollection()
	if err != nil {
		return nil, err
	}

	return m.Queries.GetQueryByLevelAndID(level, levelID, query.QueryID), nil
}

func (m *MCPBackend) CreateNewQuery(query Cx1ClientGo.SASTQuery) (*Cx1ClientGo.SASTQuery, error) {
	m.sessionRefresh()
	q, _, err := m.Cx1Client.CreateNewSASTQuery(m.session, query)
	if err != nil {
		return nil, err
	}

	err = m.UpdateQueryCollection()
	if err != nil {
		return nil, err
	}

	return m.Queries.GetQueryByLevelAndID(q.Level, q.LevelID, query.QueryID), nil
}

func (m *MCPBackend) UpdateQueryCollection() error {
	m.logger.Debugf("Updating query collection")
	qc, err := m.Cx1Client.GetQueriesByLevelID(m.Cx1Client.QueryTypeProject(), m.Target.Project.ProjectID)
	if err != nil {
		return fmt.Errorf("failed to get queries: %v", err)
	}
	m.Queries.AddCollection(&qc)

	aq, err := m.Cx1Client.GetAllAuditSASTQueries(m.session)
	if err != nil {
		return fmt.Errorf("failed to get audit queries: %v", err)
	}

	m.Queries.AddCollection(&aq)
	return nil
}

func (m *MCPBackend) ProcessAuditResults(executedQuery *Cx1ClientGo.SASTQuery, results *Cx1ClientGo.QueryRun, code string) string {
	if len(results.FailedQueries) > 0 {
		return m.ProcessRunFailures(executedQuery, results, code)
	}

	return m.ProcessRunResults(executedQuery, results)
}

func (m *MCPBackend) ProcessRunResults(executedQuery *Cx1ClientGo.SASTQuery, results *Cx1ClientGo.QueryRun) string {
	response := strings.Builder{}

	if len(results.Results) > 0 {
		vulnCount := 0
		for _, r := range results.Results {
			vulns, err := m.GetRunResults(r)
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
						productQuery := m.Queries.FindQuery(m.Cx1Client.QueryTypeProduct(), "", executedQuery.Language, queryName, 0)
						if productQuery != nil {
							runQuery = productQuery
						} else {
							tenantQuery := m.Queries.FindQuery(m.Cx1Client.QueryTypeTenant(), "", executedQuery.Language, queryName, 0)
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
						if err := m.VulnAugment(i, queryName, v); err != nil {
							m.logger.Errorf("Failed to augment code with %s vuln %s", queryName, v)
						} else {
							vulnCount++
						}
					}
				} else {
					m.logger.Infof("Failed to get query from title: %s", r.Title)
				}
			}
		}

		if vulnCount > 0 {
			response.WriteString("\nSource code:\n")
			response.WriteString(m.GetCodeSnippets())
		}
	}

	return response.String()
}

func (m *MCPBackend) ProcessRunFailures(executedQuery *Cx1ClientGo.SASTQuery, results *Cx1ClientGo.QueryRun, code string) string {
	response := strings.Builder{}

	if len(results.FailedQueries) > 0 {
		//cs := backend.NewCodeSet()
		for _, f := range results.FailedQueries {
			q, err := m.UpdateQueryByKey(f.QueryID)
			if err != nil {
				fmt.Fprintf(&response, "Error: Failed to retrieve query with key %s: %s", f.QueryID, err)
				response.WriteString("\n")
			}
			var fs FileSource
			if q.EditorKey == executedQuery.EditorKey {
				fs = NewFileSource(code)
			} else {
				fs = NewFileSource(q.Source)
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

	return response.String()
}
