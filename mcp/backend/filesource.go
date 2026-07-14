package backend

import (
	"slices"
	"strings"
)

type FileAug struct {
	Src string
	Msg string
}

type FileSource struct {
	code    []string
	Sources map[string]struct{} // augment sources
	Augs    map[uint64][]FileAug
}

func NewFileSource(code string) FileSource {
	return FileSource{
		code:    strings.Split(strings.ReplaceAll(code, "\r\n", "\n"), "\n"),
		Sources: make(map[string]struct{}),
		Augs:    make(map[uint64][]FileAug),
	}
}

func (f *FileSource) Augment(src, msg string, line uint64) {
	f.Augs[line-1] = append(f.Augs[line-1], FileAug{Src: src, Msg: msg})
	if _, ok := f.Sources[src]; !ok {
		f.Sources[src] = struct{}{}
	}
}

func (f *FileSource) ClearAug(src string) {
	delete(f.Sources, src)
	for line, aug := range f.Augs {
		if slices.ContainsFunc(aug, func(a FileAug) bool { return a.Src == src }) {
			f.Augs[line] = slices.DeleteFunc(aug, func(a FileAug) bool { return a.Src == src })
			if len(f.Augs[line]) == 0 {
				delete(f.Augs, line)
			}
		}
	}
}

func (f *FileSource) Code() string {
	var str strings.Builder
	for i, line := range f.code {
		str.WriteString(line)
		if augs, ok := f.Augs[uint64(i)]; ok {
			str.WriteString(" // ")
			comments := make([]string, len(augs))
			for i, aug := range augs {
				comments[i] = aug.Msg
			}
			str.WriteString(strings.Join(comments, "; "))
		}
		str.WriteString("\n")
	}
	return str.String()
}
