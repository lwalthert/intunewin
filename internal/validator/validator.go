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
