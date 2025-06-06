package ldap

import "errors"

var (
	ErrGidNumberInUse           = errors.New("gidNumber already in use")
	ErrGroupNameExists          = errors.New("group name already exists")
	ErrGroupNotFound            = errors.New("group not found")
	ErrGroupConstraintViolation = errors.New("group constraint violation (gidNumber or cn conflict)")
	ErrUserAlreadyInGroup       = errors.New("user already in group")
	ErrUserNotInGroup           = errors.New("user not in group")
	ErrUserNoGroup              = errors.New("user belongs to no group")
	ErrUserExists               = errors.New("user already exists")
	ErrUidNumberInUse           = errors.New("uidNumber already in use")
	ErrUserNotFound             = errors.New("user not found")
	ErrUserConstraintViolation  = errors.New("user constraint violation (uid or uidNumber conflict)")
	ErrPublicKeyNotFound        = errors.New("public key not found")
	ErrPublicKeyExists          = errors.New("public key already exists")
)
