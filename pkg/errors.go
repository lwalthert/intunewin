package pkg

import "errors"

var (
	ErrInvalidContentFolder = errors.New("invalid content folder")
	ErrInvalidSetupFile     = errors.New("invalid setup file")
)
