package validator

import (
	"errors"
	"os"
	"path"
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

func NotBlank(input string) bool {
	return input != ""
}
