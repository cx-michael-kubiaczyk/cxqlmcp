package backend

import (
	"fmt"
	"strings"
)

type AugmentSource string

func AugSrc_Finding(query string) AugmentSource { return AugmentSource("Finding " + query) }
func AugSrc_Audit(query string) AugmentSource   { return AugmentSource("Query " + query) }

type FileSource struct {
	code    []string
	Sources map[AugmentSource]struct{} // augment sources
	Augs    map[uint64]map[AugmentSource][]string
}

type CodeSet struct {
	Files map[string]*FileSource
}

func NewCodeSet() CodeSet {
	return CodeSet{
		Files: make(map[string]*FileSource),
	}
}

func (cs *CodeSet) AddFile(path, code string) {
	fs := NewFileSource(code)
	cs.Files[path] = &fs
}

func (cs *CodeSet) AugmentFile(filePath string, line uint64, source AugmentSource, message string) {
	if _, ok := cs.Files[filePath]; !ok {
		return
	}

	if uint64(len((*cs.Files[filePath]).code)) <= line {
		return
	}

	cs.Files[filePath].Augment(source, message, line)
}

func (cs *CodeSet) GetSources() string {
	var str strings.Builder
	for _, file := range cs.Files {
		str.WriteString(file.Code())
		str.WriteString("\n")
	}
	return str.String()
}

func (cs *CodeSet) HasFile(path string) bool {
	_, ok := cs.Files[path]
	return ok
}

func NewFileSource(code string) FileSource {
	return FileSource{
		code:    strings.Split(strings.ReplaceAll(code, "\r\n", "\n"), "\n"),
		Sources: make(map[AugmentSource]struct{}),
		Augs:    make(map[uint64]map[AugmentSource][]string),
	}
}

func (f *FileSource) Augment(src AugmentSource, msg string, line uint64) {
	if _, ok := f.Augs[line-1]; !ok {
		f.Augs[line-1] = make(map[AugmentSource][]string)
	}
	f.Augs[line-1][src] = append(f.Augs[line-1][src], msg)
	if _, ok := f.Sources[src]; !ok {
		f.Sources[src] = struct{}{}
	}
}

func (f *FileSource) ClearAug(src AugmentSource) {
	delete(f.Sources, src)

	for line := range f.Augs {
		delete(f.Augs[line], src)
	}
}

func (f *FileSource) Code() string {
	var str strings.Builder
	for i, line := range f.code {
		str.WriteString(line)
		if augs, ok := f.Augs[uint64(i)]; ok {
			str.WriteString(" // ")
			comments := make([]string, len(augs))
			a := 0
			for aug := range augs {
				comments[a] = fmt.Sprintf("%s: %s", aug, strings.Join(augs[aug], ", "))
				a++
			}
			str.WriteString(strings.Join(comments, "; "))
		}
		str.WriteString("\n")
	}
	return str.String()
}
