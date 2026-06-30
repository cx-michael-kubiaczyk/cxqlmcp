package mcp

import "testing"

func TestExtractIDFromURL(t *testing.T) {
	path := "https://deu.ast.checkmarx.net/sast-results/61595fd4-58ea-4333-b8f6-7ddaeea64880/f6d958d7-f36e-48e3-8698-79222f23af13?resultId=oxR2fXYEI%2B7J%2FWoBw4RtkzJ9YJE%3D&pagination=pageSize%3D10%3BcurrentPage%3D1&grouping=groups%255B0%255D%3Dlanguage%3Bgroups%255B1%255D%3Dseverity%3Bgroups%255B2%255D%3DqueryName"
	expectedPID := "61595fd4-58ea-4333-b8f6-7ddaeea64880"
	expectedSID := "f6d958d7-f36e-48e3-8698-79222f23af13"
	expectedRID := "oxR2fXYEI+7J/WoBw4RtkzJ9YJE="

	pid, sid, rid, err := extractIDFromURL(path)
	if err != nil {
		t.Fatalf("extractIDFromURL() unexpected error: %v", err)
	}

	if pid != expectedPID {
		t.Errorf("expected ProjectID %s, got %s", expectedPID, pid)
	}

	if sid != expectedSID {
		t.Errorf("expected ScanID %s, got %s", expectedSID, sid)
	}

	if rid != expectedRID {
		t.Errorf("expected ResultID %s, got %s", expectedRID, rid)
	}
}
