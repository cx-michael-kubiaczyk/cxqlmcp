package backend

import (
	"fmt"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

type MCPBackend struct {
	cx1client    *Cx1ClientGo.Cx1Client
	project      *Cx1ClientGo.Project
	application  *Cx1ClientGo.Application
	scan         *Cx1ClientGo.Scan
	Result       *Cx1ClientGo.ScanSASTResult
	Vuln         *Cx1ClientGo.QueryVulnerability
	session      *Cx1ClientGo.AuditSession
	logger       *logrus.Logger
	files        map[string]*FileSource // filename: code
	Queries      Cx1ClientGo.SASTQueryCollection
	descriptions map[uint64]Cx1ClientGo.SASTQueryDescription
	targetQuery  []*Cx1ClientGo.SASTQuery
}

func NewBackend(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) MCPBackend {
	return MCPBackend{cx1client: cx1client,
		logger:       logger,
		files:        make(map[string]*FileSource),
		descriptions: make(map[uint64]Cx1ClientGo.SASTQueryDescription)}
}

func (m *MCPBackend) Initialize(path string) error {
	m.logger.Debug("Getting query collection")
	qc, err := m.cx1client.GetSASTQueryCollection()
	if err != nil {
		return err
	}
	m.Queries = qc

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
func (m *MCPBackend) Shutdown() {
	if m.session != nil {
		m.endSession()
	}
}

func (m *MCPBackend) CreateAuditSession() error {
	if m.session != nil {
		m.endSession()
	}
	session, err := m.cx1client.GetAuditSessionByID("sast", m.project.ProjectID, m.scan.ScanID)
	if err != nil {
		return fmt.Errorf("failed to get audit session: %v", err)
	}
	m.session = &session

	aq, err := m.cx1client.GetAuditSASTQueriesByLevelID(m.session, m.cx1client.QueryTypeProject(), m.project.ProjectID)
	if err != nil {
		return fmt.Errorf("failed to get queries: %v", err)
	}

	m.Queries.AddCollection(&aq)

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
	err := m.sessionRefresh()
	if err != nil {
		return false, fmt.Errorf("failed to refresh audit session: %v", err)
	}

	result, err := m.cx1client.RunSASTQuery(m.session, m.closestQuery(), m.closestQuery().Source)
	if err != nil {
		return false, fmt.Errorf("failed to run query: %v", err)
	}

	m.logger.Debugf("Looking for finding: %+v", m.Result)

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
				if findingsEqual(m.Result, vuln) {
					m.Vuln = &vuln
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (m *MCPBackend) GetQueryDescription(queryId uint64) (Cx1ClientGo.SASTQueryDescription, error) {
	if desc, ok := m.descriptions[queryId]; ok {
		return desc, nil
	}

	description, err := m.cx1client.GetSASTQueryDescription(queryId)
	if err != nil {
		return Cx1ClientGo.SASTQueryDescription{}, fmt.Errorf("failed to get query description: %v", err)
	}

	m.descriptions[queryId] = description
	return description, nil
}

func (m MCPBackend) GetCodeSnippets() string {
	var str strings.Builder
	for _, file := range m.files {
		str.WriteString(file.Code())
		str.WriteString("\n")
	}
	return str.String()
}
