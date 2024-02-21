package validator

import (
	"errors"
	"os"
)

type PathType int

const (
	Directory PathType = iota
	File
)

func PathIsValid(path string, expected PathType) bool {
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
