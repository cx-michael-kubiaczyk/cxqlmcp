package backend

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
)

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
	m.Result = &result

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

	/*for file, source := range m.ScanSources.Files {
		m.logger.Debugf("File: %s\n\n%s\n", file, strings.Join(source.code, "\n"))
	}*/

	return nil

}

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
	if m.project == nil {
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

	if product != nil {
		q, err := m.Cx1Client.GetAuditSASTQueryByKey(m.session, product.EditorKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get product query source: %v", err)
		}
		product.MergeQuery(q)
	}

	if tenant != nil {
		q, err := m.Cx1Client.GetAuditSASTQueryByKey(m.session, tenant.EditorKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get tenant query source: %v", err)
		}
		tenant.MergeQuery(q)
	}

	if m.application != nil {
		application = m.Queries.GetQueryByLevelAndID(
			m.Cx1Client.QueryTypeApplication(),
			m.application.ApplicationID,
			m.Result.Data.QueryID,
		)

		if application != nil {
			q, err := m.Cx1Client.GetAuditSASTQueryByKey(m.session, application.EditorKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get application query source: %v", err)
			}
			application.MergeQuery(q)
		}
	}

	if m.project != nil {
		project = m.Queries.GetQueryByLevelAndID(
			m.Cx1Client.QueryTypeProject(),
			m.project.ProjectID,
			m.Result.Data.QueryID,
		)
		if project != nil {
			q, err := m.Cx1Client.GetAuditSASTQueryByKey(m.session, project.EditorKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get project query source: %v", err)
			}
			project.MergeQuery(q)
		}
	}

	return []*Cx1ClientGo.SASTQuery{product, tenant, application, project}, nil
}

func (m *MCPBackend) FormatQuery(query *Cx1ClientGo.SASTQuery) string {
	var result strings.Builder

	if query.Level == "Cx" {
		result.WriteString("Can edit: false\n")
	} else {
		result.WriteString("Can edit: true\n")
	}

	result.WriteString(fmt.Sprintf("Source code: \n```csharp\n%s\n```\n", query.Source))

	open, base, _ := query.GetDependencies(&m.Queries)
	if len(open)+len(base) > 0 {
		result.WriteString("The following queries are called by this query and can be edited or overridden:\n")
		for _, q := range open {
			result.WriteString(fmt.Sprintf(" - %s.%s.%s\n", q.Language, q.Group, q.Name))
		}
		for _, q := range base {
			result.WriteString(fmt.Sprintf(" - %s.%s.%s\n", q.Language, q.Group, q.Name))
		}
	}

	/*
		if len(product) > 0 {
			result.WriteString("The following product-defined functions are called and cannot be edited or overridden:\n- ")
			result.WriteString(strings.Join(product, "\n- "))
			result.WriteString("\n")
		}
	*/

	return result.String()
}

func (m *MCPBackend) FormatQueryHierarchy(queries []*Cx1ClientGo.SASTQuery) string {
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

	if product != nil {
		result.WriteString("\n[PRODUCT DEFAULT QUERY INFO]\n")
		result.WriteString(m.FormatQuery(product))
	}

	result.WriteString("\n[TENANT CUSTOM QUERY INFO]\n")
	if tenant != nil {
		result.WriteString(m.FormatQuery(tenant))
	} else {
		result.WriteString("Can create: true\n")
	}

	if m.application != nil {
		result.WriteString("\n[APPLICATION CUSTOM QUERY INFO]\n")
		if app != nil {
			result.WriteString(m.FormatQuery(app))
		} else {
			result.WriteString("Can create: true\n")
		}
	}

	result.WriteString("\n[PROJECT CUSTOM QUERY INFO]\n")
	if proj != nil {
		result.WriteString(m.FormatQuery(proj))
	} else {
		result.WriteString("Can create: true\n")
	}

	return result.String()
}

func (m *MCPBackend) closestQuery() *Cx1ClientGo.SASTQuery {
	for i := 3; i >= 0; i-- {
		if m.targetQuery[i] != nil {
			return m.targetQuery[i]
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
		if i > len(v.Nodes) {
			return false
		}
		vN := &v.Nodes[i]
		if rN.FileName == vN.FileID && rN.Line == vN.Line && rN.Column == vN.StartColumn && rN.Name == vN.Name {
			return true
		}

	}
	return false
}

func (m *MCPBackend) UpdateQueryCollection() error {
	m.logger.Debugf("Updating query collection")
	qc, err := m.Cx1Client.GetQueriesByLevelID(m.Cx1Client.QueryTypeProject(), m.project.ProjectID)
	if err != nil {
		return fmt.Errorf("failed to get queries: %v", err)
	}
	m.Queries.AddCollection(&qc)

	aq, err := m.Cx1Client.GetAuditSASTQueriesByLevelID(m.session, m.Cx1Client.QueryTypeProject(), m.project.ProjectID)
	if err != nil {
		return fmt.Errorf("failed to get audit queries: %v", err)
	}

	m.Queries.AddCollection(&aq)
	return nil
}
