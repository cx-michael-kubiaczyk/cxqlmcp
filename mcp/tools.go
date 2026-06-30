package mcp

import (
	"fmt"
)

func (m *MCP) CreateSessionFromURL(path string) error {
	err := m.initialize(path)
	if err != nil {
		return fmt.Errorf("failed to initialize session data: %v", err)
	}

	err = m.createAuditSession()
	if err != nil {
		return fmt.Errorf("failed to create audit session: %v", err)
	}

	present, err := m.checkFindingStatus()
	if err != nil {
		return fmt.Errorf("failed to check finding status: %v", err)
	}
	if !present || m.vuln == nil {
		return fmt.Errorf("The scan in web-audit did not find this finding: %s", m.result.String())
	}

	m.logger.Infof("Finding %s is present: %s", m.result.String(), m.vuln.String())

	return nil
}

func (m *MCP) GetQueryInfo(language, group, name string) (string, error) {
	queries, err := m.getQueryHierarchy(language, group, name)
	if err != nil {
		return "", err
	}

	return m.FormatQueryHierarchy(queries), nil
}

func RunQuery(path, code string) (string, error) {

	return "", nil
}

func SaveQuery(path string) error {

	return nil
}
