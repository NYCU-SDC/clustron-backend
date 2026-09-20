package internal

import (
	"clustron-backend/internal/ldap"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	"github.com/NYCU-SDC/summer/pkg/problem"
)

var (
	// Auth Errors
	ErrInvalidRefreshToken    = errors.New("invalid refresh token")
	ErrProviderNotFound       = errors.New("provider not found")
	ErrInvalidExchangeToken   = errors.New("invalid exchange token")
	ErrInvalidCallbackInfo    = errors.New("invalid callback info")
	ErrInvalidCallbackState   = errors.New("invalid callback state")
	ErrPermissionDenied       = errors.New("permission denied")
	ErrNotModuleOwner         = errors.New("user does not own this module")
	ErrAlreadyOnboarded       = errors.New("user already onboarded")
	ErrBindingAccountConflict = errors.New("binding account conflict")
	ErrNewStateFailed         = errors.New("failed to generate new state")

	// Database Errors
	ErrDatabaseConflict = errors.New("database conflict")

	// Ansible Errors
	ErrServerAlreadyExists            = errors.New("server already exists")
	ErrAllowedLoginGroupsUnsupported  = errors.New("allowed login groups can only be configured on compute nodes")
	ErrAllowedLoginGroupsRoleConflict = errors.New("clear allowed login groups before changing the server to a head node")

	// Setting Errors
	ErrInvalidPublicKey     = errors.New("invalid public key")
	ErrInvalidFingerprint   = errors.New("invalid fingerprint")
	ErrInvalidPassword      = errors.New("invalid password")
	ErrLDAPUserAlreadyBound = errors.New("LDAP user already bound to another account")

	// User Errors
	ErrInvalidFullName = errors.New("invalid full name")
	ErrInvalidRoleType = errors.New("invalid role type")
	ErrSelfDeletion    = errors.New("self deletion")

	// Group Errors
	ErrGroupNotFound = errors.New("group not found or user not in group")

	// System Group Errors
	ErrInvalidSystemGroupName   = errors.New("invalid system group name")
	ErrSystemGroupDenied        = errors.New("system group is denylisted or privileged")
	ErrSystemGroupNotDiscovered = errors.New("system group not found on any compute node")
	ErrUserHasNoLDAPAccount     = errors.New("user has no LDAP account")
)

type ErrInvalidLinuxUsername struct {
	Reason string
}

func NewConflictProblem(reason string) problem.Problem {
	return problem.Problem{
		Title:  "Conflict",
		Status: http.StatusConflict,
		Type:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/409",
		Detail: reason,
	}
}

func NewUnprocessableEntityProblem(reason string) problem.Problem {
	return problem.Problem{
		Title:  "Unprocessable Content",
		Status: http.StatusUnprocessableEntity,
		Type:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/422",
		Detail: reason,
	}
}

func (e ErrInvalidLinuxUsername) Error() string {
	return e.Reason
}

type ErrInvalidSetting struct {
	Reason string
}

func (e ErrInvalidSetting) Error() string {
	return e.Reason
}

// ErrSystemGroupGIDInconsistent reports a local group whose gid differs across compute nodes.
type ErrSystemGroupGIDInconsistent struct {
	Name string
	GIDs map[int64][]string
}

func (e ErrSystemGroupGIDInconsistent) Error() string {
	gids := make([]int64, 0, len(e.GIDs))
	for gid := range e.GIDs {
		gids = append(gids, gid)
	}
	slices.Sort(gids)
	parts := make([]string, len(gids))
	for i, gid := range gids {
		parts[i] = fmt.Sprintf("%d on %s", gid, strings.Join(e.GIDs[gid], ", "))
	}
	return fmt.Sprintf("group %q has different gids across compute nodes: %s", e.Name, strings.Join(parts, "; "))
}

// ErrSystemGroupGIDConflict reports a gid that a different local group uses on some
// compute node; registering it would grant that other group there.
type ErrSystemGroupGIDConflict struct {
	Name      string
	GIDNumber int64
	UsedBy    map[string]string // server -> other group name
}

func (e ErrSystemGroupGIDConflict) Error() string {
	servers := slices.Sorted(maps.Keys(e.UsedBy))
	parts := make([]string, len(servers))
	for i, server := range servers {
		parts[i] = fmt.Sprintf("%s on %s", e.UsedBy[server], server)
	}
	return fmt.Sprintf("gid %d of group %q is used by another group: %s", e.GIDNumber, e.Name, strings.Join(parts, ", "))
}

func NewProblemWriter() *problem.HttpWriter {
	return problem.NewWithMapping(ErrorHandler)
}

func ErrorHandler(err error) problem.Problem {
	switch {
	// Auth Errors
	case errors.Is(err, ErrInvalidRefreshToken):
		return problem.NewNotFoundProblem("refresh token not found")
	case errors.Is(err, ErrProviderNotFound):
		return problem.NewNotFoundProblem("provider not found")
	case errors.Is(err, ErrInvalidExchangeToken):
		return problem.NewValidateProblem("invalid exchange token")
	case errors.Is(err, ErrInvalidCallbackInfo):
		return problem.NewValidateProblem("invalid callback info")
	case errors.Is(err, ErrInvalidCallbackState):
		return problem.NewInternalServerProblem("invalid callback state")
	case errors.Is(err, ErrPermissionDenied):
		return problem.NewForbiddenProblem("permission denied")
	case errors.Is(err, ErrNotModuleOwner):
		return problem.NewForbiddenProblem("user does not own this module")
	case errors.Is(err, ErrBindingAccountConflict):
		return problem.NewBadRequestProblem("binding account conflict")
	case errors.Is(err, ErrAlreadyOnboarded):
		return problem.NewBadRequestProblem("user already onboarded")
	case errors.Is(err, ErrNewStateFailed):
		return problem.NewInternalServerProblem("failed to generate new state")
	// Database Errors
	case errors.Is(err, ErrDatabaseConflict):
		return NewConflictProblem("database conflict")
	case errors.Is(err, databaseutil.ErrUniqueViolation):
		return NewConflictProblem("database unique constraint conflict")
	case errors.Is(err, databaseutil.ErrForeignKeyViolation):
		return NewConflictProblem("database foreign key conflict")
	case errors.Is(err, databaseutil.ErrDeadlockDetected):
		return NewConflictProblem("database transaction could not be completed")
	// Ansible Errors
	case errors.Is(err, ErrServerAlreadyExists):
		return problem.NewBadRequestProblem(err.Error())
	case errors.Is(err, ErrAllowedLoginGroupsUnsupported):
		return NewUnprocessableEntityProblem(err.Error())
	case errors.Is(err, ErrAllowedLoginGroupsRoleConflict):
		return NewConflictProblem(err.Error())
	// Validation Errors
	case errors.Is(err, strconv.ErrSyntax):
		return problem.NewValidateProblem("invalid syntax")
	case errors.As(err, new(*json.SyntaxError)):
		return problem.NewValidateProblem("invalid JSON syntax")
	case errors.As(err, &ErrInvalidLinuxUsername{}):
		return problem.NewValidateProblem("invalid username: " + err.Error())
	case errors.As(err, &ErrInvalidSetting{}):
		return problem.NewValidateProblem("invalid setting: " + err.Error())
	// Setting Errors
	case errors.Is(err, ErrInvalidPublicKey):
		return problem.NewValidateProblem("invalid public key")
	case errors.Is(err, ErrInvalidFingerprint):
		return problem.NewBadRequestProblem("invalid fingerprint")
	case errors.Is(err, ErrInvalidPassword):
		return problem.NewValidateProblem("invalid password")
	case errors.Is(err, ErrLDAPUserAlreadyBound):
		return problem.NewBadRequestProblem("LDAP user already bound to another account")
	// User Errors
	case errors.Is(err, ErrInvalidFullName):
		return problem.NewValidateProblem("invalid full name")
	case errors.Is(err, ErrInvalidRoleType):
		return problem.NewValidateProblem("invalid role type")
	case errors.Is(err, ErrSelfDeletion):
		return problem.NewBadRequestProblem("cannot delete yourself")
	// Group Errors
	case errors.Is(err, ErrGroupNotFound):
		return problem.NewNotFoundProblem(err.Error())
	// System Group Errors
	case errors.Is(err, ErrInvalidSystemGroupName):
		return problem.NewValidateProblem(err.Error())
	case errors.Is(err, ErrSystemGroupDenied):
		return problem.NewForbiddenProblem(err.Error())
	case errors.Is(err, ErrSystemGroupNotDiscovered):
		return problem.NewNotFoundProblem(err.Error())
	case errors.Is(err, ErrUserHasNoLDAPAccount):
		return problem.NewBadRequestProblem(err.Error())
	case errors.As(err, &ErrSystemGroupGIDInconsistent{}):
		return NewConflictProblem(err.Error())
	case errors.As(err, &ErrSystemGroupGIDConflict{}):
		return NewConflictProblem(err.Error())
	// LDAP Client Errors
	case errors.Is(err, ldap.ErrGIDNumberInUse):
		return NewConflictProblem(err.Error())
	case errors.Is(err, ldap.ErrGroupNameExists):
		return NewConflictProblem(err.Error())
	case errors.Is(err, ldap.ErrGroupConstraintViolation):
		return NewConflictProblem(err.Error())
	case errors.Is(err, ldap.ErrUserNotInGroup):
		return problem.NewNotFoundProblem(err.Error())
	case errors.Is(err, ldap.ErrUserAlreadyInGroup):
		return NewConflictProblem(err.Error())
	case errors.Is(err, ldap.ErrUserNoGroup):
		return problem.NewNotFoundProblem(err.Error())
	case errors.Is(err, ldap.ErrUserExists):
		return NewConflictProblem(err.Error())
	case errors.Is(err, ldap.ErrUIDNumberInUse):
		return NewConflictProblem(err.Error())
	case errors.Is(err, ldap.ErrUserNotFound):
		return problem.NewNotFoundProblem(err.Error())
	case errors.Is(err, ldap.ErrUserConstraintViolation):
		return NewConflictProblem(err.Error())
	case errors.Is(err, ldap.ErrPublicKeyNotFound):
		return problem.NewNotFoundProblem(err.Error())
	case errors.Is(err, ldap.ErrPublicKeyExists):
		return NewConflictProblem(err.Error())
	default:
		return problem.Problem{}
	}
}
