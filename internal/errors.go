package internal

import (
	"errors"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"strconv"
)

var (
	// Auth Errors
	ErrInvalidRefreshToken  = errors.New("invalid refresh token")
	ErrProviderNotFound     = errors.New("provider not found")
	ErrInvalidExchangeToken = errors.New("invalid exchange token")
	ErrInvalidCallbackInfo  = errors.New("invalid callback info")
	ErrPermissionDenied     = errors.New("permission denied")
	ErrAlreadyOnboarded     = errors.New("user already onboarded")

	// Database Errors
	ErrDatabaseConflict = errors.New("database conflict")
)

type ErrInvalidLinuxUsername struct {
	Reason string
}

func (e ErrInvalidLinuxUsername) Error() string {
	return e.Reason
}

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
	case errors.Is(err, ErrInvalidCallbackInfo):
		return problem.NewValidateProblem("invalid callback info")
	case errors.Is(err, ErrPermissionDenied):
		return problem.NewForbiddenProblem("permission denied")
	case errors.Is(err, ErrDatabaseConflict):
		return problem.NewBadRequestProblem("database conflict")
	case errors.Is(err, ErrAlreadyOnboarded):
		return problem.NewBadRequestProblem("user already onboarded")
	case errors.Is(err, strconv.ErrSyntax):
		return problem.NewValidateProblem("invalid syntax")
	case errors.As(err, &ErrInvalidLinuxUsername{}):
		return problem.NewValidateProblem("invalid username: " + err.Error())
	default:
		return problem.Problem{}
	}
}
