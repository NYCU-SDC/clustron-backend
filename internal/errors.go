package internal

import (
	"errors"
	"github.com/NYCU-SDC/summer/pkg/problem"
)

var (
	ErrInvalidRefreshToken  = errors.New("invalid refresh token")
	ErrProviderNotFound     = errors.New("provider not found")
	ErrInvalidExchangeToken = errors.New("invalid exchange token")
)

func NewProblemWriter() *problem.HttpWriter {
	return problem.NewWithMapping(ErrorHandler)
}

func ErrorHandler(err error) problem.Problem {
	switch {
	case errors.Is(err, ErrInvalidRefreshToken):
		return problem.NewNotFoundProblem("refresh token not found")
	case errors.Is(err, ErrProviderNotFound):
		return problem.NewNotFoundProblem("provider not found")
	case errors.Is(err, ErrInvalidExchangeToken):
		return problem.NewValidateProblem("invalid exchange token")
	}
	return problem.Problem{}
}
