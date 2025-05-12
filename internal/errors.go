package internal

import (
	"errors"
	"github.com/NYCU-SDC/summer/pkg/problem"
)

var (
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

func NewProblemWriter() *problem.HttpWriter {
	return problem.NewWithMapping(ErrorHandler)
}

func ErrorHandler(err error) problem.Problem {
	switch {
	case errors.Is(err, ErrInvalidRefreshToken):
		return problem.NewNotFoundProblem("refresh token not found")
	}
	return problem.Problem{}
}
