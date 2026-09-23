package backend

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
)

const cacheDir = "./data"

// getScanSourceZip returns the source zip for scanID, using a local ./data cache
// to avoid re-downloading the same bytes from Cx1's repo store on every re-scan.
func (m *MCPBackend) getScanSourceZip(scanID string) ([]byte, error) {
	cachePath := filepath.Join(cacheDir, scanID+".zip")
	if data, err := os.ReadFile(cachePath); err == nil {
		return data, nil
	}

	data, err := m.Cx1Client.GetScanSourcesByID(scanID)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		m.logger.Errorf("failed to create cache dir %s: %v", cacheDir, err)
		return data, nil
	}
	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		m.logger.Errorf("failed to write cache file %s: %v", cachePath, err)
	}
	return data, nil
}

const guidCharset = "abcdefghijklmnopqrstuvwxyz0123456789"

// newShortID returns a random lowercase-alphanumeric string of the given length,
// safe for use inside Cx1 application/project names. It is a collision-avoidance
// id for a handful of throwaway test projects, not a security token, so the
// slight modulo bias from byte%len(guidCharset) is an accepted simplification.
func newShortID(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random id: %w", err)
	}
	for i := range b {
		b[i] = guidCharset[int(b[i])%len(guidCharset)]
	}
	return string(b), nil
}

func extractIDFromURL(path string) (ProjectID, ScanID, ResultID string, err error) {
	u, err := url.Parse(path)
	if err != nil {
		err = fmt.Errorf("failed to parse URL: %w", err)
		return
	}

	// Extract IDs from the path: /sast-results/{projectID}/{scanID}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) < 3 {
		err = fmt.Errorf("invalid URL structure: projectID or scanID missing in path")
		return
	}

	ProjectID = segments[1]
	ScanID = segments[2]
	ResultID = u.Query().Get("resultId")
	return
}

/*
func (m *MCPBackend) createCodeExtract(sid, rid string) error {
	filter := Cx1ClientGo.ScanSASTResultsFilter{
		BaseFilter: Cx1ClientGo.BaseFilter{Limit: 10},
		ScanID:     sid,
		ResultIDs:  []string{rid},
	}

	_, results, err := m.Cx1Client.GetAllScanSASTResultsFiltered(filter)
	if err != nil {
		return fmt.Errorf("failed to get results: %v", err)
	}

	if len(results) != 1 {
		return fmt.Errorf("expected 1 result, got %d", len(results))
	}

	result := results[0]
	m.Target.Result = &result

	m.logger.Debugf("Result: %+v", result)
	for i, n := range result.Data.Nodes {
		m.logger.Debugf("Node %d: %+v", i, n)
		if !m.ScanSources.HasFile(n.FileName) {
			fileSource, err := m.Cx1Client.GetScannedFileSourceByID(sid, n.FileName)
			if err != nil {
				return fmt.Errorf("failed to get file source: %v", err)
			}
			m.ScanSources.AddFile(n.FileName, fileSource)
		}

		m.ScanSources.AugmentFile(n.FileName, n.Line, AugSrc_Finding(result.Data.QueryName), fmt.Sprintf("step %d", i+1))
	}

	return nil
}
*/

/*
func (m *MCPBackend) addFile(scanId, filePath string) error {
	if _, ok := m.ScanSources.Files[filePath]; ok {
		return nil
	}

	fileSource, err := m.Cx1Client.GetScannedFileSourceByID(scanId, filePath)
	if err != nil {
		return fmt.Errorf("failed to get file source: %v", err)
	}
	m.ScanSources.AddFile(filePath, fileSource)
	return nil
}
*/

/*
func (m *MCPBackend) getZip() []byte {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	for filename, source := range m.files {
		// Clean the filename for the zip archive:
		// 1. Remove any leading slash (zip paths must be relative).
		// 2. Replace backslashes with forward slashes (zip standard).
		archiveFilename := strings.TrimPrefix(filename, "/")
		archiveFilename = strings.ReplaceAll(archiveFilename, "\\", "/")

		f, err := w.Create(archiveFilename)
		if err != nil {
			m.logger.Errorf("failed to create zip entry for %s (original: %s): %v", archiveFilename, filename, err)
			continue
		}
		content := source.Code()
		if _, err := f.Write([]byte(content)); err != nil {
			m.logger.Errorf("failed to write zip content for %s: %v", filename, err)
			continue
		}
		m.logger.Debugf("Created zip entry for %s", filename)
	}

	if err := w.Close(); err != nil {
		m.logger.Errorf("failed to close zip writer: %v", err)
	}
	return buf.Bytes()
}
*/

func (m *MCPBackend) GetQueryHierarchy(language, group, name string) ([]*Cx1ClientGo.SASTQuery, error) {
	if m.Target.Project == nil {
		return nil, fmt.Errorf("no project loaded")
	}
	var product, tenant, application, project *Cx1ClientGo.SASTQuery

	product = m.Queries.GetQueryByLevelAndName(
		m.Cx1Client.QueryTypeProduct(),
		m.Cx1Client.QueryTypeProduct(),
		language,
		group,
		name,
	)

	tenant = m.Queries.GetQueryByLevelAndName(
		m.Cx1Client.QueryTypeTenant(),
		m.Cx1Client.QueryTypeTenant(),
		language,
		group,
		name,
	)

	if product == nil && tenant == nil {
		return nil, fmt.Errorf("no query found for %s %s %s", language, group, name)
	}

	queryId := uint64(0)

	if product != nil {
		m.logger.Debugf("Got product query %s", product.StringDetailed())
		q, err := m.Cx1Client.GetAuditSASTQueryByKey(m.session, product.EditorKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get product query source: %v", err)
		}
		product.MergeQuery(q)
		queryId = q.QueryID
	}

	if tenant != nil {
		m.logger.Debugf("Got tenant query %s", tenant.StringDetailed())
		q, err := m.Cx1Client.GetAuditSASTQueryByKey(m.session, tenant.EditorKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get tenant query source: %v", err)
		}
		tenant.MergeQuery(q)
		if queryId == 0 {
			queryId = q.QueryID
		}
	}

	if m.Target.Application != nil {
		application = m.Queries.GetQueryByLevelAndID(
			m.Cx1Client.QueryTypeApplication(),
			m.Target.Application.ApplicationID,
			queryId,
		)

		if application != nil {
			m.logger.Debugf("Got application query %s", application.StringDetailed())
			q, err := m.Cx1Client.GetAuditSASTQueryByKey(m.session, application.EditorKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get application query source: %v", err)
			}
			application.MergeQuery(q)
		}
	}

	if m.Target.Project != nil {
		project = m.Queries.GetQueryByLevelAndID(
			m.Cx1Client.QueryTypeProject(),
			m.Target.Project.ProjectID,
			queryId,
		)
		if project != nil {
			m.logger.Debugf("Got project query %s", project.StringDetailed())
			q, err := m.Cx1Client.GetAuditSASTQueryByKey(m.session, project.EditorKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get project query source: %v", err)
			}
			project.MergeQuery(q)
		}
	}

	return []*Cx1ClientGo.SASTQuery{product, tenant, application, project}, nil
}

func (m *MCPBackend) FormatQuery(query *Cx1ClientGo.SASTQuery, edit bool) string {
	var result strings.Builder

	if query.Level == "Cx" {
		result.WriteString("Can edit: false\n")
	} else if edit {
		result.WriteString("Can edit: true\n")
	}

	result.WriteString(fmt.Sprintf("Source code: \n```csharp\n%s\n```\n", query.Source))

	open, base, _ := query.GetDependencies(&m.Queries)
	if len(open)+len(base) > 0 {
		result.WriteString("The following queries are called by this query:\n")
		for _, q := range open {
			result.WriteString(fmt.Sprintf(" - %s.%s.%s\n", q.Language, q.Group, q.Name))
		}
		for _, q := range base {
			result.WriteString(fmt.Sprintf(" - %s.%s.%s\n", q.Language, q.Group, q.Name))
		}
	}

	return result.String()
}

func (m *MCPBackend) FormatQueryHierarchy(queries []*Cx1ClientGo.SASTQuery, view, edit []bool) string {
	var result strings.Builder

	var product = queries[0]
	var tenant = queries[1]
	var app = queries[2]
	var proj = queries[3]

	if product != nil {
		result.WriteString("[QUERY INFO]\n")
		result.WriteString(fmt.Sprintf("The query %s - %s - %s is included in the product\n", product.Language, product.Group, product.Name))
	} else if tenant != nil {
		result.WriteString("[QUERY INFO]\n")
		result.WriteString(fmt.Sprintf("The query %s - %s - %s is created by the customer in the tenant\n", tenant.Language, tenant.Group, tenant.Name))
	}

	if product != nil && view[0] {
		result.WriteString("\n[PRODUCT DEFAULT QUERY INFO]\n")
		result.WriteString(m.FormatQuery(product, edit[0]))
	}

	if product.Language != "Common" { // can't override common-language
		if view[1] {
			result.WriteString("\n[TENANT-LEVEL QUERY INFO]\n")
			if tenant != nil {
				result.WriteString(m.FormatQuery(tenant, edit[1]))
			} else if edit[1] {
				result.WriteString("Doens't exist, can be created\n")
			} else {
				result.WriteString("Does not exist, cannot create (out of scope)\n")
			}
		}

		if m.Target.Application != nil && view[2] {
			result.WriteString("\n[APPLICATION-LEVEL QUERY INFO]\n")
			if app != nil {
				result.WriteString(m.FormatQuery(app, edit[2]))
			} else if edit[2] {
				result.WriteString("Doens't exist, can be created\n")
			} else {
				result.WriteString("Does not exist, cannot create (out of scope)\n")
			}
		}

		if view[3] {
			result.WriteString("\n[PROJECT-LEVEL QUERY INFO]\n")
			if proj != nil {
				result.WriteString(m.FormatQuery(proj, edit[3]))
			} else if edit[3] {
				result.WriteString("Doens't exist, can be created\n")
			} else {
				result.WriteString("Does not exist, cannot create (out of scope)\n")
			}
		}
	}

	return result.String()
}

func (m *MCPBackend) closestQuery() *Cx1ClientGo.SASTQuery {
	for i := 3; i >= 0; i-- {
		if m.Target.Query[i] != nil {
			return m.Target.Query[i]
		}
	}
	return nil
}

func (m *MCPBackend) sessionRefresh() error {
	if m.session == nil {
		return m.CreateAuditSession()
	}

	err := m.Cx1Client.AuditSessionKeepAlive(m.session)
	if err == nil {
		return nil
	}

	m.endSession()
	return m.CreateAuditSession()
}

func (m *MCPBackend) endSession() {
	if m.session != nil {
		err := m.Cx1Client.DeleteAuditSession(m.session)
		if err != nil {
			m.logger.Errorf("failed to terminate audit session: %v", err)
		}
		m.session = nil
	}
}

func findingsEqual(r *Cx1ClientGo.ScanSASTResult, v Cx1ClientGo.QueryVulnerability) bool {
	for i, rN := range r.Data.Nodes {
		if i >= len(v.Nodes) {
			return false
		}
		vN := &v.Nodes[i]
		if rN.FileName == vN.FileID && rN.Line == vN.Line && rN.Column == vN.StartColumn && rN.Name == vN.Name {
			return true
		}

	}
	return false
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

// createProject creates one project inside the given application and assigns
// it the given preset. The preset assignment persists for future scans of the
// same project, so it only needs to be set once here.
func (m *MCPBackend) createProject(applicationName, projectName, presetName string) (Cx1ClientGo.Project, error) {
	project, _, err := m.Cx1Client.GetOrCreateProjectInApplicationByName(projectName, applicationName)
	if err != nil {
		return project, fmt.Errorf("failed to create project: %v", err)
	}
	if err := m.Cx1Client.SetProjectPresetByID(project.ProjectID, presetName, false); err != nil {
		return project, fmt.Errorf("failed to assign preset: %v", err)
	}
	return project, nil
}

// scanProject uploads sourceZip to an existing project and triggers (but does not
// poll) a scan using whatever preset is currently assigned to the project. This is
// reusable both for a project's initial scan and for later re-scans (e.g. by
// ScanControlProjects) after a query override has changed.
func (m *MCPBackend) scanProject(projectID string, sourceZip []byte, branch string) (Cx1ClientGo.Scan, error) {
	uploadUrl, err := m.Cx1Client.UploadBytes(&sourceZip)
	if err != nil {
		return Cx1ClientGo.Scan{}, fmt.Errorf("failed to upload source: %v", err)
	}

	if branch == "" {
		branch = "main"
	}
	scanConfig := &Cx1ClientGo.ScanConfigurationSet{}
	scanConfig.AddScanEngine("sast")
	scan, err := m.Cx1Client.ScanProjectZipByID(projectID, uploadUrl, branch, scanConfig.Configurations, map[string]string{})
	if err != nil {
		return scan, fmt.Errorf("failed to trigger scan: %v", err)
	}
	return scan, nil
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

func (m *MCPBackend) checkControlFindingStatus(scanID string) (bool, error) {
	results, err := m.Cx1Client.GetAllScanSASTResultsByID(scanID)
	if err != nil {
		return false, err
	}

	for _, r := range results {
		if r.Data.QueryID == m.Target.QueryID {
			return true, nil
		}
	}
	return false, nil
}
