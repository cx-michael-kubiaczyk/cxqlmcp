package backend

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed cxqldocs/cxql_api_docs.jsonl
var cxqlDocsJSONL []byte

// CxQLDoc is one chunk of the CxQL API reference (a CxList method, a
// definition, an operator table, etc.), embedded from a static JSONL
// export of the CxQuery API Guide. See CLAUDE.md for provenance.
type CxQLDoc struct {
	ID       string            `json:"id"`
	Text     string            `json:"text"`
	Metadata map[string]string `json:"metadata"`
}

var cxqlDocs []CxQLDoc

func init() {
	for _, line := range strings.Split(string(cxqlDocsJSONL), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var d CxQLDoc
		if err := json.Unmarshal([]byte(line), &d); err == nil {
			cxqlDocs = append(cxqlDocs, d)
		}
	}
}

var cxqlDocTokenPattern = regexp.MustCompile(`[a-zA-Z0-9_.]+`)

func tokenizeCxQLQuery(query string) []string {
	tokens := cxqlDocTokenPattern.FindAllString(strings.ToLower(query), -1)
	seen := make(map[string]bool, len(tokens))
	unique := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if !seen[t] {
			seen[t] = true
			unique = append(unique, t)
		}
	}
	return unique
}

// SearchCxQLDocs performs a simple keyword search over the embedded CxQL API
// reference. Query tokens found in a doc's title score higher than tokens
// found only in the body text or other metadata fields. Zero-score docs are
// dropped; the remainder are returned in descending score order.
func (m *MCPBackend) SearchCxQLDocs(query string, maxResults int) []CxQLDoc {
	tokens := tokenizeCxQLQuery(query)
	if len(tokens) == 0 {
		return nil
	}

	type scoredDoc struct {
		doc   CxQLDoc
		score int
	}
	scored := make([]scoredDoc, 0, len(cxqlDocs))

	for _, d := range cxqlDocs {
		title := strings.ToLower(d.Metadata["title"])
		body := strings.ToLower(d.Text)
		var other strings.Builder
		for k, v := range d.Metadata {
			if k == "title" {
				continue
			}
			other.WriteString(strings.ToLower(v))
			other.WriteString(" ")
		}
		otherText := other.String()

		score := 0
		for _, t := range tokens {
			if strings.Contains(title, t) {
				score += 5
			}
			if strings.Contains(body, t) {
				score += 2
			}
			if strings.Contains(otherText, t) {
				score++
			}
		}
		if score > 0 {
			scored = append(scored, scoredDoc{d, score})
		}
	}

	sort.SliceStable(scored, func(i, j int) bool { return scored[i].score > scored[j].score })

	if maxResults > 0 && len(scored) > maxResults {
		scored = scored[:maxResults]
	}
	results := make([]CxQLDoc, len(scored))
	for i, s := range scored {
		results[i] = s.doc
	}
	return results
}

// cxqlDocFieldOrder lists the well-known metadata fields in the order they
// should be rendered; any other metadata keys (eg. numbered "Example N"
// variants or stray cxEnv.* fields from source-doc cleanup quirks) are
// appended afterwards in alphabetical order.
var cxqlDocFieldOrder = []string{"Syntax", "Typeparameters", "Parameters", "Returns", "Exceptions", "Remarks"}

// FormatCxQLDocResults renders CxQL doc search results in the bracket-header
// style used elsewhere in this package (see FormatQueryHierarchy).
func (m *MCPBackend) FormatCxQLDocResults(docs []CxQLDoc) string {
	var result strings.Builder

	for _, d := range docs {
		title := d.Metadata["title"]
		if index := d.Metadata["index"]; index != "" {
			result.WriteString(fmt.Sprintf("[CxQL DOC: %s (%s)]\n", title, index))
		} else {
			result.WriteString(fmt.Sprintf("[CxQL DOC: %s]\n", title))
		}
		if d.Text != "" {
			result.WriteString(d.Text)
			result.WriteString("\n")
		}

		handled := map[string]bool{"title": true, "index": true}
		for _, field := range cxqlDocFieldOrder {
			if v, ok := d.Metadata[field]; ok && v != "" {
				result.WriteString(fmt.Sprintf("%s: %s\n", field, v))
			}
			handled[field] = true
		}

		remaining := make([]string, 0, len(d.Metadata))
		for k := range d.Metadata {
			if !handled[k] {
				remaining = append(remaining, k)
			}
		}
		sort.Strings(remaining)
		for _, k := range remaining {
			if v := d.Metadata[k]; v != "" {
				result.WriteString(fmt.Sprintf("%s: %s\n", k, v))
			}
		}

		result.WriteString("\n")
	}

	return strings.TrimRight(result.String(), "\n") + "\n"
}
