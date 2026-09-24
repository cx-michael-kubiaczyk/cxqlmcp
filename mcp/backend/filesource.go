package backend

import (
	"fmt"
	"sort"
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

func (cs *CodeSet) GetFile(path string) (*FileSource, bool) {
	fs, ok := cs.Files[path]
	return fs, ok
}

// FilePaths returns the paths of all loaded source files, sorted alphabetically.
func (cs *CodeSet) FilePaths() []string {
	paths := make([]string, 0, len(cs.Files))
	for path := range cs.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

type CodeSearchMatch struct {
	Path string
	Line int // 1-indexed
	Text string
}

// Search looks for substring (case-insensitive) across every loaded source
// file and returns each matching line, sorted by file path then line number.
func (cs *CodeSet) Search(substring string) []CodeSearchMatch {
	var matches []CodeSearchMatch
	if substring == "" {
		return matches
	}
	needle := strings.ToLower(substring)
	for _, path := range cs.FilePaths() {
		fs := cs.Files[path]
		for i, line := range fs.code {
			if strings.Contains(strings.ToLower(line), needle) {
				matches = append(matches, CodeSearchMatch{Path: path, Line: i + 1, Text: line})
			}
		}
	}
	return matches
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
		str.WriteString(f.augComment(i))
		str.WriteString("\n")
	}
	return str.String()
}

// LineCount returns the number of lines in the file.
func (f *FileSource) LineCount() int {
	return len(f.code)
}

// CodeRange renders lines lineStart..lineEnd (1-indexed, inclusive), each
// prefixed with its line number, with the same inline dataflow annotations
// used by Code(). The range is clamped to the file's bounds.
func (f *FileSource) CodeRange(lineStart, lineEnd int) string {
	if lineStart < 1 {
		lineStart = 1
	}
	if lineEnd > len(f.code) {
		lineEnd = len(f.code)
	}

	var str strings.Builder
	for i := lineStart - 1; i < lineEnd; i++ {
		fmt.Fprintf(&str, "%d: %s", i+1, f.code[i])
		str.WriteString(f.augComment(i))
		str.WriteString("\n")
	}
	return str.String()
}

// augComment renders the " // Source: message; ..." suffix for line index i
// (0-indexed), or "" if the line has no annotations.
func (f *FileSource) augComment(i int) string {
	augs, ok := f.Augs[uint64(i)]
	if !ok {
		return ""
	}
	comments := make([]string, len(augs))
	a := 0
	for aug := range augs {
		comments[a] = fmt.Sprintf("%s: %s", aug, strings.Join(augs[aug], ", "))
		a++
	}
	return " // " + strings.Join(comments, "; ")
}
