package handlers

import (
	"fmt"
	"os"
	"strings"
)

// Capture managed files without exposing their contents in errors or output.
func snapshotEdgeFiles(paths []string) (func() error, error) {
	traefikACMEMu.Lock()
	defer traefikACMEMu.Unlock()
	type savedFile struct {
		path   string
		data   []byte
		mode   os.FileMode
		exists bool
	}
	var files []savedFile
	for _, path := range paths {
		file := savedFile{path: path}
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect managed edge file: %w", err)
		}
		if err == nil {
			info, err := os.Stat(path)
			if err != nil {
				return nil, fmt.Errorf("inspect managed edge file: %w", err)
			}
			file.data, file.mode, file.exists = data, info.Mode().Perm(), true
		}
		files = append(files, file)
	}
	return func() error {
		traefikACMEMu.Lock()
		defer traefikACMEMu.Unlock()
		var failures []string
		for _, file := range files {
			var err error
			if file.exists {
				err = writeFileAtomic(file.path, file.data, file.mode)
			} else {
				err = os.Remove(file.path)
				if os.IsNotExist(err) {
					err = nil
				}
			}
			if err != nil {
				failures = append(failures, err.Error())
			}
		}
		if len(failures) != 0 {
			return fmt.Errorf("restore managed edge files: %s", strings.Join(failures, "; "))
		}
		return nil
	}, nil
}
