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

func (m *MCPBackend) configureCustomPreset() (Cx1ClientGo.Preset, error) {
	presetName := "CxQL-" + m.Target.TestAppGUID
	targetQueryCollection := Cx1ClientGo.SASTQueryCollection{}
	query := m.Queries.GetQueryByID(m.Target.QueryID)
	if query == nil {
		return Cx1ClientGo.Preset{}, fmt.Errorf("unable to find target query %s with ID %d", m.Target.Result.Data.QueryName, m.Target.Result.Data.QueryID)
	}
	targetQueryCollection.AddQuery(*query)

	preset, err := m.Cx1Client.GetPresetByName("sast", presetName)
	if err != nil {
		if strings.HasPrefix(err.Error(), "no such preset") {
			preset, err = m.Cx1Client.CreateSASTPreset(presetName, "Test preset for CxQL MCP", targetQueryCollection)
			if err != nil {
				return Cx1ClientGo.Preset{}, fmt.Errorf("failed to create custom preset: %v", err)
			}
			return preset, nil
		}
		return Cx1ClientGo.Preset{}, fmt.Errorf("failed to get custom preset: %v", err)
	}

	preset.UpdateQueries(targetQueryCollection)
	if err := m.Cx1Client.UpdateSASTPreset(preset); err != nil {
		return Cx1ClientGo.Preset{}, fmt.Errorf("failed to update custom preset: %v", err)
	}
	return preset, nil
}

// createAndScanProject creates one project inside the given application, assigns
// it the given preset, uploads the given source zip, and triggers (but does not
// poll) a scan. Returns the created project, the triggered (unpolled) scan, and
// an error if any step failed.
func (m *MCPBackend) createAndScanProject(applicationID, projectName, presetName string, sourceZip []byte, branch string) (Cx1ClientGo.Project, Cx1ClientGo.Scan, error) {
	project, err := m.Cx1Client.CreateProjectInApplication(projectName, []string{}, map[string]string{}, applicationID)
	if err != nil {
		return project, Cx1ClientGo.Scan{}, fmt.Errorf("failed to create project: %v", err)
	}

	if err := m.Cx1Client.SetProjectPresetByID(project.ProjectID, presetName, false); err != nil {
		return project, Cx1ClientGo.Scan{}, fmt.Errorf("failed to assign preset: %v", err)
	}

	uploadUrl, err := m.Cx1Client.UploadBytes(&sourceZip)
	if err != nil {
		return project, Cx1ClientGo.Scan{}, fmt.Errorf("failed to upload source: %v", err)
	}

	if branch == "" {
		branch = "main"
	}
	scanConfig := &Cx1ClientGo.ScanConfigurationSet{}
	scanConfig.AddScanEngine("sast")
	scan, err := m.Cx1Client.ScanProjectZipByID(project.ProjectID, uploadUrl, branch, scanConfig.Configurations, map[string]string{})
	if err != nil {
		return project, scan, fmt.Errorf("failed to trigger scan: %v", err)
	}
	return project, scan, nil
}

// projectSpec describes one project to be created as part of a test environment:
// either the target finding's project (Label == "Target") or a TP/TN control project.
type projectSpec struct {
	label           string
	index           int
	projectName     string
	sourceProjectID string
	sourceScanID    string
}

// specResult holds the outcome of creating+scanning one projectSpec.
type specResult struct {
	spec    projectSpec
	project *Cx1ClientGo.Project
	scan    *Cx1ClientGo.Scan
	err     error
}

// CreateTestEnvironment builds a disposable Cx1 Application containing a full-source
// copy of the current target project/scan (m.project/m.scan, populated by a prior
// call to Initialize), plus one control project per tpFindings/tnFindings entry.
// All projects share one preset containing only the target finding's query.
// On success, m.project/m.application/m.scan are reassigned to the new target
// project/app/scan so subsequent audit-session calls operate on the copy.
// Returns a human-readable per-project summary, and an error only if the target
// project/scan itself failed (TP/TN failures are reported in the summary only).
func (m *MCPBackend) CreateTestEnvironment(result *Cx1ClientGo.ScanSASTResult, scan *Cx1ClientGo.Scan, tpFindings, tnFindings []string) (string, error) {
	if scan == nil || result == nil {
		return "", fmt.Errorf("no target project/scan loaded")
	}

	guid, err := newShortID(10)
	if err != nil {
		return "", fmt.Errorf("failed to generate test id: %v", err)
	}
	m.Target.TestAppGUID = guid

	app, err := m.Cx1Client.CreateApplication("CxQL-" + guid)
	if err != nil {
		return "", fmt.Errorf("failed to create test application: %v", err)
	}
	m.Target.Application = &app

	if _, err := m.configureCustomPreset(); err != nil {
		return "", fmt.Errorf("failed to configure preset: %v", err)
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
		return "", err
	}
	for i, sid := range tnFindings {
		scan, err := m.Cx1Client.GetScanByID(sid)
		if err != nil {
			return "", fmt.Errorf("failed to get TN source scan %s: %v", sid, err)
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
	results := make([]specResult, len(specs))
	for i, spec := range specs {
		m.logger.Debugf("Processing %s %d: source scan ID %s", spec.label, spec.index, spec.sourceScanID)
		sourceZip, err := m.Cx1Client.GetScanSourcesByID(spec.sourceScanID)
		if err != nil {
			results[i] = specResult{spec: spec, err: fmt.Errorf("failed to fetch source: %v", err)}
			continue
		}
		project, scan, err := m.createAndScanProject(app.ApplicationID, spec.projectName, "CxQL-"+m.Target.TestAppGUID, sourceZip, "test")
		results[i] = specResult{spec: spec, project: &project, scan: &scan, err: err}
	}

	// Second pass: poll every scan that was triggered successfully.
	for i := range results {
		if results[i].err != nil {
			continue
		}
		polled, err := m.Cx1Client.ScanPollingDetailed(results[i].scan)
		if err != nil {
			results[i].err = fmt.Errorf("scan polling failed: %v", err)
			continue
		}
		results[i].scan = &polled
	}

	summary := strings.Builder{}
	var targetErr error
	for _, r := range results {
		name := r.spec.label
		if r.spec.label != "Target" {
			name = fmt.Sprintf("%s-%d", r.spec.label, r.spec.index)
		}

		if r.err != nil {
			fmt.Fprintf(&summary, "%s: FAILED - %v\n", name, r.err)
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

		fmt.Fprintf(&summary, "%s: created project %s (%s), scan %s status %s\n", name, r.spec.projectName, r.project.ProjectID, r.scan.ScanID, r.scan.Status)

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
		return summary.String(), fmt.Errorf("failed to create target project: %v", targetErr)
	}

	if results[0].err != nil {
		return summary.String(), fmt.Errorf("target FP repro scan failed: %s", results[0].err)
	}

	scanresults, err := m.Cx1Client.GetAllScanSASTResultsByID(results[0].scan.ScanID)
	if err != nil {
		return summary.String(), fmt.Errorf("failed to get scan results for target repro scan %s: %s", results[0].scan.ScanID, err)
	}

	for _, r := range scanresults {
		if r.SimilarityID == result.SimilarityID && r.Data.QueryID == result.Data.QueryID {
			m.Target.Result = &r
			break
		}
	}

	return summary.String(), nil
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
		return "", fmt.Errorf("failed to get project query source: %v", err)
	}
	query.MergeQuery(q)
	query.Source = q.Source
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
		m.ScanSources.AugmentFile(v.FileID, v.Line, AugSrc_Audit(fmt.Sprintf("%s #%d", query, number)), fmt.Sprintf("step %d", i+1))
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

func (m *MCPBackend) CreateOverride(query *Cx1ClientGo.SASTQuery) (*Cx1ClientGo.SASTQuery, error) {
	m.sessionRefresh()
	_, err := m.Cx1Client.CreateSASTQueryOverride(m.session, m.Cx1Client.QueryTypeProject(), query)
	if err != nil {
		return nil, err
	}

	err = m.UpdateQueryCollection()
	if err != nil {
		return nil, err
	}

	return m.Queries.GetQueryByLevelAndID(m.Cx1Client.QueryTypeProject(), m.Target.Project.ProjectID, query.QueryID), nil
}
