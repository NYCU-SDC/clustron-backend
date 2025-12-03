package ldap

import (
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

func (c *Client) CreateUser(uid string, cn string, sn string, sshPublicKey string, uidNumber string) error {
	base := "ou=People," + c.Config.LDAPBaseDN

	// check if uid is in use
	filter := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(uid))
	exist, err := c.entryExists(base, filter)
	if err != nil {
		c.Logger.Error("failed to check uid existence", zap.String("uid", uid), zap.Error(err))
		return fmt.Errorf("failed to check uid existence: %w", err)
	}
	if exist {
		c.Logger.Warn("user already exists", zap.String("uid", uid))
		return fmt.Errorf("%w: %s", ErrUserExists, uid)
	}

	// check if uidNumber is in use
	filter = fmt.Sprintf("(uidNumber=%s)", ldap.EscapeFilter(uidNumber))
	exist, err = c.entryExists(base, filter)
	if err != nil {
		c.Logger.Error("failed to check uidNumber existence", zap.String("uidNumber", uidNumber), zap.Error(err))
		return fmt.Errorf("failed to check uidNumber existence: %w", err)
	}
	if exist {
		c.Logger.Warn("uidNumber already exists", zap.String("uidNumber", uidNumber))
		return fmt.Errorf("%w: %s", ErrUIDNumberInUse, uidNumber)
	}

	// create user
	const gidNumber = "10000"
	dn := fmt.Sprintf("uid=%s,%s", uid, base)

	addRequest := ldap.NewAddRequest(dn, nil)
	addRequest.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount", "ldapPublicKey"})
	addRequest.Attribute("uid", []string{uid})
	addRequest.Attribute("cn", []string{cn})
	addRequest.Attribute("sn", []string{sn})
	addRequest.Attribute("userPassword", []string{"<invalid>"})
	if sshPublicKey != "" {
		addRequest.Attribute("sshPublicKey", []string{sshPublicKey})
	}
	addRequest.Attribute("uidNumber", []string{uidNumber})
	addRequest.Attribute("gidNumber", []string{gidNumber})
	addRequest.Attribute("homeDirectory", []string{fmt.Sprintf("/home/%s", uid)})
	addRequest.Attribute("loginShell", []string{"/bin/bash"})

	err = c.Conn.Add(addRequest)
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) {
			switch ldapErr.ResultCode {
			case ldap.LDAPResultEntryAlreadyExists:
				return fmt.Errorf("%w: %s", ErrUserExists, uid)
			case ldap.LDAPResultConstraintViolation:
				c.Logger.Warn("constraint violation detected",
					zap.String("uid", uid), zap.String("uidNumber", uidNumber), zap.Error(err))
				return fmt.Errorf("%w: %s", ErrUserConstraintViolation, uid)
			}
		}
		c.Logger.Error("failed to create user", zap.String("uid", uid), zap.Error(err))
		return fmt.Errorf("failed to create user: %w", err)
	}

	c.Logger.Info("user created",
		zap.String("uid", uid), zap.String("uidNumber", uidNumber))

	return nil
}

func (c *Client) GetUserInfo(uid string) (*ldap.Entry, error) {
	base := "ou=People," + c.Config.LDAPBaseDN
	filter := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(uid))
	attributes := []string{
		"dn", "uid", "cn", "sn", "sshPublicKey", "homeDirectory", "loginShell",
	}

	result, err := c.SearchByFilter(base, filter, attributes)
	if err != nil {
		c.Logger.Error("failed to search user", zap.String("uid", uid), zap.Error(err))
		return nil, fmt.Errorf("failed to search user: %w", err)
	}

	if len(result.Entries) == 0 {
		c.Logger.Warn("user not found", zap.String("uid", uid))
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, uid)
	}
	return result.Entries[0], nil
}

func (c *Client) GetUserInfoByUIDNumber(uidNumber string) (*ldap.Entry, error) {
	base := "ou=People," + c.Config.LDAPBaseDN
	filter := fmt.Sprintf("(uidNumber=%s)", ldap.EscapeFilter(uidNumber))
	attributes := []string{
		"dn", "uid", "cn", "sn", "sshPublicKey", "homeDirectory", "loginShell",
	}

	result, err := c.SearchByFilter(base, filter, attributes)
	if err != nil {
		c.Logger.Error("failed to search user", zap.String("uidNumber", uidNumber), zap.Error(err))
		return nil, fmt.Errorf("failed to search user: %w", err)
	}

	if len(result.Entries) == 0 {
		c.Logger.Warn("user not found", zap.String("uidNumber", uidNumber))
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, uidNumber)
	}
	return result.Entries[0], nil
}

func (c *Client) ExistUser(uid string) (bool, error) {
	base := "ou=People," + c.Config.LDAPBaseDN
	filter := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(uid))

	exist, err := c.entryExists(base, filter)
	if err != nil {
		c.Logger.Error("failed to check user existence", zap.String("uid", uid), zap.Error(err))
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}
	return exist, nil
}

func (c *Client) UpdateUser(uid string, cn string, sn string) error {
	dn := fmt.Sprintf("uid=%s,ou=People,%s", uid, c.Config.LDAPBaseDN)
	modifyRequest := ldap.NewModifyRequest(dn, nil)
	modifyRequest.Replace("cn", []string{cn})
	modifyRequest.Replace("sn", []string{sn})

	err := c.Conn.Modify(modifyRequest)
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			c.Logger.Warn("user not found when updating", zap.String("uid", uid))
			return fmt.Errorf("%w: %s", ErrUserNotFound, uid)
		}
		c.Logger.Error("failed to update user", zap.String("uid", uid), zap.Error(err))
		return fmt.Errorf("failed to update user: %w", err)
	}

	c.Logger.Info("user updated successfully", zap.String("uid", uid))
	return nil
}

func (c *Client) DeleteUser(uid string) error {
	dn := fmt.Sprintf("uid=%s,ou=People,%s", uid, c.Config.LDAPBaseDN)
	deleteRequest := ldap.NewDelRequest(dn, nil)

	err := c.Conn.Del(deleteRequest)
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			c.Logger.Warn("user not found when deleting", zap.String("uid", uid))
			return fmt.Errorf("%w: %s", ErrUserNotFound, uid)
		}
		c.Logger.Error("failed to delete user", zap.String("uid", uid), zap.Error(err))
		return fmt.Errorf("failed to delete user: %w", err)
	}

	c.Logger.Info("user deleted successfully", zap.String("uid", uid))
	return nil
}

func (c *Client) GetUsedUIDNumbers() ([]string, error) {
	base := "ou=People," + c.Config.LDAPBaseDN
	filter := "(uidNumber=*)"
	attributes := []string{"uidNumber"}

	result, err := c.SearchByFilter(base, filter, attributes)
	if err != nil {
		c.Logger.Error("failed to search for uidNumbers", zap.Error(err))
		return nil, fmt.Errorf("failed to retrieve uidNumbers: %w", err)
	}

	var uidNumbers []string
	for _, entry := range result.Entries {
		uid := entry.GetAttributeValue("uidNumber")
		if uid != "" {
			uidNumbers = append(uidNumbers, uid)
		}
	}

	return uidNumbers, nil
}

func (c *Client) ExistSSHPublicKey(publicKey string) (bool, error) {
	base := "ou=People," + c.Config.LDAPBaseDN
	filter := fmt.Sprintf("(sshPublicKey=%s)", ldap.EscapeFilter(publicKey))

	exist, err := c.entryExists(base, filter)
	if err != nil {
		c.Logger.Error("failed to check SSH public key existence", zap.Error(err))
		return false, fmt.Errorf("failed to check SSH public key existence: %w", err)
	}
	return exist, nil
}

func (c *Client) AddSSHPublicKey(uid string, publicKey string) error {
	dn := fmt.Sprintf("uid=%s,ou=People,%s", uid, c.Config.LDAPBaseDN)

	modifyRequest := ldap.NewModifyRequest(dn, nil)
	modifyRequest.Add("sshPublicKey", []string{publicKey})

	err := c.Conn.Modify(modifyRequest)
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) {
			switch ldapErr.ResultCode {
			case ldap.LDAPResultNoSuchObject:
				return fmt.Errorf("%w: %s", ErrUserNotFound, uid)
			case ldap.LDAPResultAttributeOrValueExists:
				return fmt.Errorf("%w: %s", ErrPublicKeyExists, uid)
			}
		}
		c.Logger.Error("failed to add SSH public key", zap.String("uid", uid), zap.Error(err))
		return fmt.Errorf("failed to add SSH public key: %w", err)
	}

	c.Logger.Info("SSH public key added", zap.String("uid", uid))
	return nil
}

func (c *Client) DeleteSSHPublicKey(uid string, publicKey string) error {
	dn := fmt.Sprintf("uid=%s,ou=People,%s", uid, c.Config.LDAPBaseDN)

	modifyRequest := ldap.NewModifyRequest(dn, nil)
	modifyRequest.Delete("sshPublicKey", []string{publicKey})

	err := c.Conn.Modify(modifyRequest)

	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) {
			switch ldapErr.ResultCode {
			case ldap.LDAPResultNoSuchObject:
				return fmt.Errorf("%w: %s", ErrUserNotFound, uid)
			case ldap.LDAPResultNoSuchAttribute:
				return fmt.Errorf("%w: %s", ErrPublicKeyNotFound, uid)
			}
		}
		c.Logger.Error("failed to delete SSH public key", zap.String("uid", uid), zap.Error(err))
		return fmt.Errorf("failed to delete SSH public key: %w", err)
	}

	c.Logger.Info("SSH public key deleted", zap.String("uid", uid))
	return nil
}

func (c *Client) GetAllUIDNumbers() ([]string, error) {
	base := "ou=People," + c.Config.LDAPBaseDN
	filter := "(uidNumber=*)"
	attributes := []string{"uidNumber"}

	result, err := c.SearchByFilter(base, filter, attributes)
	if err != nil {
		c.Logger.Error("failed to search for uidNumbers", zap.Error(err))
		return nil, fmt.Errorf("failed to retrieve uidNumbers: %w", err)
	}

	var uidNumbers []string
	for _, entry := range result.Entries {
		uid := entry.GetAttributeValue("uidNumber")
		if uid != "" {
			uidNumbers = append(uidNumbers, uid)
		}
	}

	return uidNumbers, nil
}
