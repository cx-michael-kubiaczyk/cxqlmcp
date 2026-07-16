package backend

import (
	"strings"
	"testing"
)

func TestFilesourceAugment(t *testing.T) {
	sourceCode := []string{"This is", "a few lines", "of code"}

	fs := FileSource{
		code:    sourceCode,
		Sources: make(map[AugmentSource]struct{}),
		Augs:    make(map[uint64]map[AugmentSource][]string),
	}

	expect := strings.Join(sourceCode, "\n") + "\n"
	actual := fs.Code()
	if strings.Compare(expect, actual) != 0 {
		t.Errorf("Unchanged source code does not match expected value.\n%s\n =/= \n%s", actual, expect)
	}

	fs.Augment("Finding X", "step 1", 2)
	fs.Augment("Finding X", "step 2", 1)
	expectedCode1 := []string{"This is // Finding X: step 2", "a few lines // Finding X: step 1", "of code"}
	expect = strings.Join(expectedCode1, "\n") + "\n"
	actual = fs.Code()

	if strings.Compare(expect, actual) != 0 {
		t.Errorf("Source code with 1 augment does not match expected value.\n%s\n =/= \n%s", actual, expect)
	}

	fs.Augment("Audit Y", "step 1", 1)
	expectedCode2 := []string{"This is // Finding X: step 2; Audit Y: step 1", "a few lines // Finding X: step 1", "of code"}
	expect = strings.Join(expectedCode2, "\n") + "\n"
	actual = fs.Code()

	if strings.Compare(expect, actual) != 0 {
		t.Errorf("Source code with 2 augments does not match expected value.\n%s\n =/= \n%s", actual, expect)
	}
}
