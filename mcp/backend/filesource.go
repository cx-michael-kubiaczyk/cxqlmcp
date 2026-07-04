package backend

import "fmt"

type FileSource []string

func (f *FileSource) Augment(queryName string, nodeNumber int, line uint64) {
	(*f)[line-1] = (*f)[line-1] + fmt.Sprintf("// Finding %s step %d", queryName, nodeNumber+1)
}
