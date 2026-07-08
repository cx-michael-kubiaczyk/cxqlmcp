package backend

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cxpsemea/Cx1ClientGo"
)

func TestMatchingFindings(t *testing.T) {
	vulnBytes := []byte(`{"vulnerabilityId":"68265895-98ce-42a9-abdd-ed6c211bb82c","state":"","pathSize":1,"nodes":[{"name":"end","language":"javascript","fullName":"CxJSNS_be31c95d.Lambda.Lambda.end","typeName":"end","line":17,"startColumn":32,"endColumn":35,"domType":"MethodInvokeExpr","nodeId":301,"fileId":"/JavaScript_HSTS_FP.js"}],"sourceFile":"/JavaScript_HSTS_FP.js","sourceLine":17,"sourceId":301,"sourceName":"end","sourceType":"MethodInvokeExpr","destinationFile":"/JavaScript_HSTS_FP.js","destinationLine":17,"destinationId":301,"destinationName":"end","destinationType":"MethodInvokeExpr"}`)

	var vuln Cx1ClientGo.QueryVulnerability
	json.Unmarshal(vulnBytes, &vuln)

	resultBytes := []byte(`{"changeDetails":{"engineVersionChanged":false,"engineVersionChangeDetails":"","queryChanged":false,"queryChangeDetails":"","codeChanged":false,"codeChangeDetails":""},"compliances":["ASA Premium","Base Preset","OWASP ASVS","OWASP Top 10 2021","PCI DSS v4.0"],"confidenceLevel":0,"cvssScore":4.9275,"cweID":346,"firstFoundAt":"2026-06-18T06:20:33Z","firstScanID":"8130f76b-c6dc-487e-a2a4-54be9f6a5945","foundAt":"2026-06-18T06:20:33Z","group":"JavaScript_Medium_Threat","id":"","languageName":"javascript","nodes":[{"column":32,"fileName":"/JavaScript_HSTS_FP.js","fullName":"CxJSNS_be31c95d.Lambda.Lambda.end","length":3,"line":17,"methodLine":15,"method":"Lambda","name":"end","nodeID":301,"domType":"MethodInvokeExpr"}],"pathSystemID":"Z6ZsAZogrxT9WY99pVuEDiLbbFA=","projectID":"","queryID":7630264517191277634,"queryIDStr":"7630264517191277634","queryName":"Missing_HSTS_Header","resultHash":"Z6ZsAZogrxT9WY99pVuEDiLbbFA=","severity":"MEDIUM","similarityID":421930393,"state":"TO_VERIFY","status":"NEW","tenantID":"","uniqueID":0}`)
	result := bytesToResult(resultBytes)

	str, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("Result: \n%s\n", str)
	str, _ = json.MarshalIndent(vuln, "", "  ")
	t.Logf("Vuln: \n%s\n", str)

	cmp := findingsEqual(&result, vuln)

	if !cmp {
		t.Errorf("Findings do not match")
	}
}

func TestDifferentFindings(t *testing.T) {
	vulnBytes := []byte(`{"vulnerabilityId":"68265895-98ce-42a9-abdd-ed6c211bb82c","state":"","pathSize":1,"nodes":[{"name":"test","language":"javascript","fullName":"CxJSNS_be31c95d.Lambda.Lambda.test","typeName":"test","line":17,"startColumn":32,"endColumn":35,"domType":"MethodInvokeExpr","nodeId":301,"fileId":"/JavaScript_HSTS_FP.js"}],"sourceFile":"/JavaScript_HSTS_FP.js","sourceLine":17,"sourceId":301,"sourceName":"test","sourceType":"MethodInvokeExpr","destinationFile":"/JavaScript_HSTS_FP.js","destinationLine":17,"destinationId":301,"destinationName":"test","destinationType":"MethodInvokeExpr"}`)

	var vuln Cx1ClientGo.QueryVulnerability
	json.Unmarshal(vulnBytes, &vuln)

	resultBytes := []byte(`{"changeDetails":{"engineVersionChanged":false,"engineVersionChangeDetails":"","queryChanged":false,"queryChangeDetails":"","codeChanged":false,"codeChangeDetails":""},"compliances":["ASA Premium","Base Preset","OWASP ASVS","OWASP Top 10 2021","PCI DSS v4.0"],"confidenceLevel":0,"cvssScore":4.9275,"cweID":346,"firstFoundAt":"2026-06-18T06:20:33Z","firstScanID":"8130f76b-c6dc-487e-a2a4-54be9f6a5945","foundAt":"2026-06-18T06:20:33Z","group":"JavaScript_Medium_Threat","id":"","languageName":"javascript","nodes":[{"column":32,"fileName":"/JavaScript_HSTS_FP.js","fullName":"CxJSNS_be31c95d.Lambda.Lambda.end","length":3,"line":17,"methodLine":15,"method":"Lambda","name":"end","nodeID":301,"domType":"MethodInvokeExpr"}],"pathSystemID":"Z6ZsAZogrxT9WY99pVuEDiLbbFA=","projectID":"","queryID":7630264517191277634,"queryIDStr":"7630264517191277634","queryName":"Missing_HSTS_Header","resultHash":"Z6ZsAZogrxT9WY99pVuEDiLbbFA=","severity":"MEDIUM","similarityID":421930393,"state":"TO_VERIFY","status":"NEW","tenantID":"","uniqueID":0}`)
	result := bytesToResult(resultBytes)

	str, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("Result: \n%s\n", str)
	str, _ = json.MarshalIndent(vuln, "", "  ")
	t.Logf("Vuln: \n%s\n", str)

	cmp := findingsEqual(&result, vuln)

	if cmp {
		t.Errorf("Findings should match")
	}
}

func bytesToResult(b []byte) Cx1ClientGo.ScanSASTResult {
	var r struct {
		CweID           int
		Compliances     []string
		ConfidenceLevel int
		FirstFoundAt    time.Time
		FoundAt         time.Time
		CreatedAt       time.Time
		FirstScanId     string
		Group           string
		Language        string `json:"languageName"`
		Nodes           []Cx1ClientGo.ScanSASTResultNodes
		QueryID         uint64
		QueryIDStr      string
		QueryName       string
		ResultHash      string
		Severity        string
		SimilarityID    int64
		State           string
		Status          string
		CVSSScore       float64
		ProjectID       string
		ScanID          string
		SourceFileName  string
	}

	json.Unmarshal(b, &r)

	return Cx1ClientGo.ScanSASTResult{
		ScanResultBase: Cx1ClientGo.ScanResultBase{
			Type:            "sast",
			ResultID:        r.ResultHash,
			SimilarityID:    fmt.Sprintf("%d", r.SimilarityID),
			Status:          r.Status,
			State:           r.State,
			Severity:        r.Severity,
			ConfidenceLevel: r.ConfidenceLevel,
			FirstFoundAt:    r.FirstFoundAt,
			FoundAt:         r.FoundAt,
			FirstScanId:     r.FirstScanId,
			Description:     "",
			CVSSScore:       r.CVSSScore,
			ProjectID:       r.ProjectID,
			ScanID:          r.ScanID,
			SourceFileName:  r.SourceFileName,
		},
		Data: Cx1ClientGo.ScanSASTResultData{
			QueryID:      r.QueryID,
			QueryName:    r.QueryName,
			Group:        r.Group,
			ResultHash:   r.ResultHash,
			LanguageName: r.Language,
			Nodes:        r.Nodes,
		},
		VulnerabilityDetails: Cx1ClientGo.ScanSASTResultDetails{
			CweId:       r.CweID,
			Compliances: r.Compliances,
		},
	}
}

func TestQueryFormat(t *testing.T) {
	data := []byte(`[
  {
    "queryID": "7630264517191277634",
    "level": "Cx",
    "levelId": "Cx",
    "path": "queries/JavaScript/JavaScript_Medium_Threat/Missing_HSTS_Header/Missing_HSTS_Header.cs",
    "queryName": "Missing_HSTS_Header",
    "group": "JavaScript_Medium_Threat",
    "language": "JavaScript",
    "severity": "Medium",
    "cweID": 346,
    "isExecutable": true,
    "queryDescriptionId": 1333,
    "custom": false,
    "key": "IN4C2STBOZQVGY3SNFYHILKKMF3GCU3DOJUXA5C7JVSWI2LVNVPVI2DSMVQXILKNNFZXG2LOM5PUQU2UKNPUQZLBMRSXE===",
    "sastId": 5404,
    "source": "result = Common_Medium_Threat.Missing_HSTS_Header().SanitizeCxList(Find_HSTS_Sanitize());"
  },
  null,
  null,
  null
]`)
	var queries []*Cx1ClientGo.SASTQuery
	err := json.Unmarshal(data, &queries)
	if err != nil {
		t.Errorf("Failed to unmarshal queries data: %s", err)
		return
	}

	data, err = os.ReadFile("../queries.json")
	if err != nil {
		t.Errorf("Failed to read queries.json: %s", err)
		return
	}

	var qc Cx1ClientGo.SASTQueryCollection
	err = json.Unmarshal(data, &qc)
	if err != nil {
		t.Errorf("Failed to unmarshal queries data: %s", err)
		return
	}

	m := MCPBackend{
		Queries: qc,
	}

	formatted := m.FormatQueryHierarchy(queries)
	fmt.Printf("Formatted queries: \n%s\n", formatted)

}

func TestQueryCalls(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "queries.json"))
	if err != nil {
		t.Errorf("Failed to read queries.json: %s", err)
		return
	}

	var qc Cx1ClientGo.SASTQueryCollection
	err = json.Unmarshal(data, &qc)
	if err != nil {
		t.Errorf("Failed to unmarshal queries data: %s", err)
		return
	}

	q := qc.GetQueryByLevelAndID("Cx", "Cx", 7630264517191277634)
	if q == nil {
		t.Error("Failed to find JavaScript Missing_HSTS_Header query with ID 7630264517191277634")
		return
	}

	open, base, product := q.GetDependencies(&qc)
	t.Logf("Open calls: %v", open)
	t.Logf("Base calls: %v", base)
	t.Logf("Product calls: %v", product)

	if len(open) != 1 || open[0].Name != "Find_HSTS_Sanitize" {
		t.Errorf("Failed to find open call to Find_HSTS_Sanitize")
	}
	if len(base) != 0 {
		t.Errorf("Expected 0 base calls, found %d: %+v", len(base), base)
	}
	if len(product) != 2 || !slices.Contains(product, "SanitizeCxList") || !slices.Contains(product, "Common_Medium_Threat.Missing_HSTS_Header") {
		t.Errorf("Expected 2 product calls (SanitizeCxList, Common_Medium_Threat.Missing_HSTS_Header), found %d: %+v", len(product), product)
	}
}
