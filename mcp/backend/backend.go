package backend

import (
	"fmt"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

type MCPBackend struct {
	Cx1Client    *Cx1ClientGo.Cx1Client
	project      *Cx1ClientGo.Project
	application  *Cx1ClientGo.Application
	scan         *Cx1ClientGo.Scan
	Result       *Cx1ClientGo.ScanSASTResult
	Vuln         *Cx1ClientGo.QueryVulnerability
	session      *Cx1ClientGo.AuditSession
	logger       *logrus.Logger
	ScanSources  CodeSet
	Queries      Cx1ClientGo.SASTQueryCollection
	descriptions map[uint64]Cx1ClientGo.SASTQueryDescription
	targetQuery  []*Cx1ClientGo.SASTQuery
}

func NewBackend(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) MCPBackend {
	return MCPBackend{Cx1Client: cx1client,
		logger:       logger,
		ScanSources:  NewCodeSet(),
		descriptions: make(map[uint64]Cx1ClientGo.SASTQueryDescription),
	}
}

func (m *MCPBackend) Initialize(path string) error {
	m.logger.Debug("Getting query collection")
	qc, err := m.Cx1Client.GetSASTQueryCollection()
	if err != nil {
		return err
	}
	m.Queries = qc

	pid, sid, rid, err := extractIDFromURL(path)
	if err != nil {
		return err
	}

	project, err := m.Cx1Client.GetProjectByID(pid)
	if err != nil {
		return fmt.Errorf("failed to get project: %v", err)
	}
	m.project = &project

	if len(*project.Applications) == 1 {
		app, err := m.Cx1Client.GetApplicationByID((*project.Applications)[0])
		if err != nil {
			return fmt.Errorf("failed to get application: %v", err)
		}
		m.application = &app
	}

	scan, err := m.Cx1Client.GetScanByID(sid)
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
func (m *MCPBackend) Shutdown() {
	if m.session != nil {
		m.endSession()
	}
}

func (m *MCPBackend) CreateAuditSession() error {
	if m.session != nil {
		m.endSession()
	}
	session, err := m.Cx1Client.GetAuditSessionByID("sast", m.project.ProjectID, m.scan.ScanID)
	if err != nil {
		return fmt.Errorf("failed to get audit session: %v", err)
	}
	m.session = &session

	if err = m.UpdateQueryCollection(); err != nil {
		return err
	}

	query := m.Queries.GetQueryByID(m.Result.Data.QueryID)
	if query == nil {
		return fmt.Errorf("failed to find query with ID %d", m.Result.Data.QueryID)
	}
	m.logger.Debugf("Finding is from query %s", query.String())

	m.targetQuery, err = m.GetQueryHierarchy(query.Language, query.Group, query.Name)
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

	m.logger.Debugf("Looking for finding: %+v", m.Result)
	for _, r := range result.Results {
		vulns, err := m.GetRunResults(r)
		if err != nil {
			return false, fmt.Errorf("Error getting results: %s", err)
		} else {
			for _, v := range vulns {
				if findingsEqual(m.Result, v) {
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
			fileSource, err := m.Cx1Client.GetScannedFileSourceByID(m.scan.ScanID, v.FileID)
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

	return m.Queries.GetQueryByLevelAndID(m.Cx1Client.QueryTypeProject(), m.project.ProjectID, query.QueryID), nil
}
