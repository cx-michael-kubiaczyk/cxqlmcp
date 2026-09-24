package backend

import (
	"strings"
	"testing"
)

func TestSearchCxQLDocsMatch(t *testing.T) {
	var m MCPBackend

	docs := m.SearchCxQLDocs("InfluencingOn", 5)
	if len(docs) == 0 {
		t.Fatalf("expected at least one result for %q, got none", "InfluencingOn")
	}
	found := false
	for _, d := range docs {
		if strings.Contains(strings.ToLower(d.Metadata["title"]), "influencingon") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a result with 'InfluencingOn' in its title, got: %+v", docs)
	}

	formatted := m.FormatCxQLDocResults(docs)
	if !strings.Contains(formatted, "[CxQL DOC:") {
		t.Errorf("expected formatted output to contain a doc header, got: %s", formatted)
	}
}

func TestSearchCxQLDocsNoMatch(t *testing.T) {
	var m MCPBackend

	docs := m.SearchCxQLDocs("zzznonexistenttokenzzz", 5)
	if len(docs) != 0 {
		t.Errorf("expected no results for a nonsense query, got %d", len(docs))
	}
}
