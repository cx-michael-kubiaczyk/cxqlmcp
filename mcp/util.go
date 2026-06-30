package mcp

import (
	"archive/zip"
	"bytes"
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

func (m *MCP) createCodeExtract(sid, rid string) error {
	filter := Cx1ClientGo.ScanSASTResultsFilter{
		BaseFilter: Cx1ClientGo.BaseFilter{Limit: 10},
		ScanID:     sid,
		ResultIDs:  []string{rid},
	}

	_, results, err := m.cx1client.GetAllScanSASTResultsFiltered(filter)
	if err != nil {
		return fmt.Errorf("failed to get results: %v", err)
	}

	if len(results) != 1 {
		return fmt.Errorf("expected 1 result, got %d", len(results))
	}

	result := results[0]
	m.result = &result

	m.logger.Infof("Result: %+v", result)
	for i, n := range result.Data.Nodes {
		m.logger.Infof("Node %d: %+v", i, n)
		if err := m.addFile(sid, n.FileName); err != nil {
			return fmt.Errorf("failed to add file: %v", err)
		}

		m.augmentFile(n.FileName, i, n, result.Data.QueryName)
	}

	for file, source := range m.files {
		m.logger.Infof("File: %s\n\n%s\n", file, strings.Join(*source, "\n"))
	}

	return nil

}

func (m *MCP) addFile(scanId, filePath string) error {
	if _, ok := m.files[filePath]; ok {
		return nil
	}

	fileSource, err := m.cx1client.GetScannedFileSourceByID(scanId, filePath)
	if err != nil {
		return fmt.Errorf("failed to get file source: %v", err)
	}
	sources := FileSource(strings.Split(strings.ReplaceAll(fileSource, "\r\n", "\n"), "\n"))
	m.files[filePath] = &sources
	return nil
}

func (m *MCP) augmentFile(filePath string, nodeNumber int, node Cx1ClientGo.ScanSASTResultNodes, queryName string) {
	if _, ok := m.files[filePath]; !ok {
		return
	}

	if uint64(len(*m.files[filePath])) <= node.Line {
		return
	}

	m.files[filePath].Augment(queryName, nodeNumber, node.Line)
}

func (m *MCP) getZip() []byte {
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
		content := strings.Join(*source, "\n")
		if _, err := f.Write([]byte(content)); err != nil {
			m.logger.Errorf("failed to write zip content for %s: %v", filename, err)
			continue
		}
		m.logger.Infof("Created zip entry for %s", filename)
	}

	if err := w.Close(); err != nil {
		m.logger.Errorf("failed to close zip writer: %v", err)
	}
	return buf.Bytes()
}

func (m *MCP) initialize(path string) error {
	pid, sid, rid, err := extractIDFromURL(path)
	if err != nil {
		return err
	}
	m.files = make(map[string]*FileSource)

	project, err := m.cx1client.GetProjectByID(pid)
	if err != nil {
		return fmt.Errorf("failed to get project: %v", err)
	}
	m.project = &project

	if len(*project.Applications) == 1 {
		app, err := m.cx1client.GetApplicationByID((*project.Applications)[0])
		if err != nil {
			return fmt.Errorf("failed to get application: %v", err)
		}
		m.application = &app
	}

	scan, err := m.cx1client.GetScanByID(sid)
	if err != nil {
		return fmt.Errorf("failed to get scan: %v", err)
	}
	m.scan = &scan

	err = m.createCodeExtract(sid, rid)
	if err != nil {
		return fmt.Errorf("failed to create code extract: %v", err)
	}

	return nil
}

func (m *MCP) getQueryHierarchy(language, group, name string) ([]*Cx1ClientGo.SASTQuery, error) {
	var product, tenant, application, project *Cx1ClientGo.SASTQuery

	product = m.queries.GetQueryByLevelAndName(
		m.cx1client.QueryTypeProduct(),
		m.cx1client.QueryTypeProduct(),
		language,
		group,
		name,
	)

	tenant = m.queries.GetQueryByLevelAndName(
		m.cx1client.QueryTypeTenant(),
		m.cx1client.QueryTypeTenant(),
		language,
		group,
		name,
	)

	if product == nil && tenant == nil {
		return nil, fmt.Errorf("no query found for %s %s %s", language, group, name)
	}

	if product != nil {
		q, err := m.cx1client.GetAuditSASTQueryByKey(m.session, product.EditorKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get product query source: %v", err)
		}
		product.MergeQuery(q)
	}

	if tenant != nil {
		q, err := m.cx1client.GetAuditSASTQueryByKey(m.session, tenant.EditorKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get tenant query source: %v", err)
		}
		tenant.MergeQuery(q)
	}

	if m.application != nil {
		application = m.queries.GetQueryByLevelAndID(
			m.cx1client.QueryTypeApplication(),
			m.application.ApplicationID,
			m.result.Data.QueryID,
		)

		if application != nil {
			q, err := m.cx1client.GetAuditSASTQueryByKey(m.session, application.EditorKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get application query source: %v", err)
			}
			application.MergeQuery(q)
		}
	}

	if m.project != nil {
		project = m.queries.GetQueryByLevelAndID(
			m.cx1client.QueryTypeProject(),
			m.project.ProjectID,
			m.result.Data.QueryID,
		)
		if project != nil {
			q, err := m.cx1client.GetAuditSASTQueryByKey(m.session, project.EditorKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get project query source: %v", err)
			}
			project.MergeQuery(q)
		}
	}

	return []*Cx1ClientGo.SASTQuery{product, tenant, application, project}, nil
}

func (m *MCP) FormatQuery(query *Cx1ClientGo.SASTQuery) string {
	var result strings.Builder

	if query.Level == "Cx" {
		result.WriteString("Can edit: false\n")
	} else {
		result.WriteString("Can edit: true\n")
	}

	open, base, product := query.GetDependencies(&m.queries)
	if len(open)+len(base) > 0 {
		result.WriteString("The following queries are called by this query and can be edited or overridden:\n")
		for _, q := range open {
			result.WriteString(fmt.Sprintf(" - %s.%s.%s\n", q.Language, q.Group, q.Name))
		}
		for _, q := range base {
			result.WriteString(fmt.Sprintf(" - %s.%s.%s\n", q.Language, q.Group, q.Name))
		}
	}
	fmt.Printf("Query calls: %+v, %+v, %+v\n", open, base, product)

	result.WriteString(fmt.Sprintf("Source code: \n```\n%s\n```\n", query.Source))

	return result.String()
}

func (m *MCP) FormatQueryHierarchy(queries []*Cx1ClientGo.SASTQuery) string {
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

func (m *MCP) createAuditSession() error {
	session, err := m.cx1client.GetAuditSessionByID("sast", m.project.ProjectID, m.scan.ScanID)
	if err != nil {
		return fmt.Errorf("failed to get audit session: %v", err)
	}
	m.session = &session

	aq, err := m.cx1client.GetAuditSASTQueriesByLevelID(m.session, m.cx1client.QueryTypeProject(), m.project.ProjectID)
	if err != nil {
		return fmt.Errorf("failed to get queries: %v", err)
	}

	m.queries.AddCollection(&aq)

	query := m.queries.GetQueryByID(m.result.Data.QueryID)
	if query == nil {
		return fmt.Errorf("failed to find query with ID %d", m.result.Data.QueryID)
	}
	m.logger.Infof("Finding is from query %s", query.String())

	m.targetQuery, err = m.getQueryHierarchy(query.Language, query.Group, query.Name)
	if err != nil {
		return fmt.Errorf("failed to get query hierarchy: %v", err)
	}

	return nil
}

func (m *MCP) checkFindingStatus() (bool, error) {
	m.vuln = nil
	err := m.sessionRefresh()
	if err != nil {
		return false, fmt.Errorf("failed to refresh audit session: %v", err)
	}

	result, err := m.cx1client.RunSASTQuery(m.session, m.closestQuery(), m.closestQuery().Source)
	if err != nil {
		return false, fmt.Errorf("failed to run query: %v", err)
	}

	m.logger.Infof("Looking for finding: %+v", m.result)

	for _, r := range result.Results {
		vulnerabilities, err := m.cx1client.GetQueryRunResultsByID(m.session, r.RunID)
		if err != nil {
			return false, fmt.Errorf("Error getting results: %s", err)
		} else {
			for _, v := range vulnerabilities {
				vuln, err := m.cx1client.GetQueryRunVulnerabilityByID(m.session, r.RunID, v.VulnerabilityID)
				if err != nil {
					return false, fmt.Errorf("Error getting vulnerability: %s", err)
				}
				if findingsEqual(m.result, vuln) {
					m.vuln = &vuln
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (m *MCP) closestQuery() *Cx1ClientGo.SASTQuery {
	for i := 3; i >= 0; i-- {
		if m.targetQuery[i] != nil {
			return m.targetQuery[i]
		}
	}
	return nil
}

func (m *MCP) sessionRefresh() error {
	if m.session == nil {
		return m.createAuditSession()
	}

	err := m.cx1client.AuditSessionKeepAlive(m.session)
	if err == nil {
		return nil
	}

	m.endSession()
	return m.createAuditSession()
}

func (m *MCP) endSession() {
	if m.session != nil {
		err := m.cx1client.DeleteAuditSession(m.session)
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
