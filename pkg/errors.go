package pkg

import "errors"

var (
	ErrorInvalidContentFolder = errors.New("invalid content folder")
	ErrorInvalidSetupFile     = errors.New("invalid setup file")
)
