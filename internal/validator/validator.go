package validator

import (
	"errors"
	"os"
	"path"
	"strings"
)

type PathType int

const (
	Directory PathType = iota
	File
)

type Validator struct {
	Errors map[string]string
}

func New() *Validator {
	return &Validator{Errors: make(map[string]string)}
}

func (v *Validator) Valid() bool {
	return len(v.Errors) == 0
}

func (v *Validator) AddError(key, message string) {
	_, exists := v.Errors[key]
	if !exists {
		v.Errors[key] = message
	}
}

func (v *Validator) Check(ok bool, key, message string) {
	if !ok {
		v.AddError(key, message)
	}
}

func PathIsExists(path string, expected PathType) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}

	switch expected {
	case Directory:
		return stat.IsDir()
	case File:
		return !stat.IsDir()
	default:
		panic(errors.New("got invalid PathType as Input"))
	}
}

func FileIsInDirectory(file, directory string) bool {
	path := path.Join(directory, file)
	return PathIsExists(path, File)
}

// IsRelativePath reports whether the given path is a plain file name or a
// relative path such as "bin/setup.exe" that does not start at a filesystem
// root. Absolute paths (e.g. "/abs/setup.exe") and Windows drive or UNC roots
// (e.g. "C:\\setup.exe", "\\\\server\\share") are rejected.
func IsRelativePath(path string) bool {
	if path == "" {
		return false
	}
	// A leading separator marks a root on Unix or Windows.
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) {
		return false
	}
	// Reject Windows drive-letter roots such as "C:" or "C:\\setup.exe".
	if len(path) >= 2 && isLetter(path[0]) && path[1] == ':' {
		return false
	}
	return true
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func NotBlank(input string) bool {
	return input != ""
}
