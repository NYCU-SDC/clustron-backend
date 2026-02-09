package ldap

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

func (c *Client) CreateGroup(groupName string, gidNumber string, memberUids []string) error {
	base := "ou=Groups," + c.Config.LDAPBaseDN

	filter := fmt.Sprintf("(gidNumber=%s)", ldap.EscapeFilter(gidNumber))
	exist, err := c.entryExists(base, filter)
	if err != nil {
		c.Logger.Error("failed to check gidNumber existence", zap.String("gidNumber", gidNumber), zap.Error(err))
		return fmt.Errorf("failed to check gidNumber existence: %w", err)
	}
	if exist {
		c.Logger.Warn("gidNumber already exists", zap.String("gidNumber", gidNumber))
		return fmt.Errorf("%w: %s", ErrGIDNumberInUse, gidNumber)
	}

	filter = fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(groupName))
	exist, err = c.entryExists(base, filter)
	if err != nil {
		c.Logger.Error("failed to check group name existence", zap.String("groupName", groupName), zap.Error(err))
		return fmt.Errorf("failed to check group name existence: %w", err)
	}
	if exist {
		c.Logger.Warn("group name already exists", zap.String("groupName", groupName))
		return fmt.Errorf("%w: %s", ErrGroupNameExists, groupName)
	}

	dn := fmt.Sprintf("cn=%s,ou=Groups,%s", groupName, c.Config.LDAPBaseDN)
	addRequest := ldap.NewAddRequest(dn, nil)
	addRequest.Attribute("objectClass", []string{"top", "posixGroup"})
	addRequest.Attribute("cn", []string{groupName})
	addRequest.Attribute("gidNumber", []string{gidNumber})
	for _, memberUid := range memberUids {
		addRequest.Attribute("memberUid", []string{memberUid})
	}

	err = c.Conn.Add(addRequest)
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) {
			switch ldapErr.ResultCode {
			case ldap.LDAPResultEntryAlreadyExists:
				return fmt.Errorf("%w: %s", ErrGroupNameExists, groupName)
			case ldap.LDAPResultConstraintViolation:
				c.Logger.Warn("constraint violation detected (probably gidNumber or cn duplicate)",
					zap.String("groupName", groupName), zap.String("gidNumber", gidNumber), zap.Error(err))
				return fmt.Errorf("%w: %s", ErrGroupConstraintViolation, groupName)
			}
		}
		c.Logger.Error("failed to create group", zap.String("group_name", groupName), zap.Error(err))
		return fmt.Errorf("failed to create group: %w", err)
	}

	c.Logger.Info("group created", zap.String("groupName", groupName), zap.String("gidNumber", gidNumber))
	return nil
}

func (c *Client) GetGroupInfo(groupName string) (*ldap.Entry, error) {
	filter := fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(groupName))
	attributes := []string{"dn", "cn", "memberUid"}

	result, err := c.SearchByFilter("ou=Groups,"+c.Config.LDAPBaseDN, filter, attributes)
	if err != nil {
		c.Logger.Error("failed to search group", zap.String("groupName", groupName), zap.Error(err))
		return nil, fmt.Errorf("failed to search group: %w", err)
	}

	if len(result.Entries) == 0 {
		c.Logger.Warn("group not found", zap.String("groupName", groupName))
		return nil, fmt.Errorf("%w: %s", ErrGroupNotFound, groupName)
	}

	return result.Entries[0], nil
}

func (c *Client) DeleteGroup(groupName string) error {
	dn := fmt.Sprintf("cn=%s,ou=Groups,%s", groupName, c.Config.LDAPBaseDN)
	deleteRequest := ldap.NewDelRequest(dn, nil)
	err := c.Conn.Del(deleteRequest)
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			c.Logger.Warn("Group does not exist", zap.String("group_name", groupName))
			return fmt.Errorf("%w: %s", ErrGroupNotFound, groupName)
		}
		c.Logger.Error("Failed to delete group", zap.String("group_name", groupName), zap.Error(err))
		return fmt.Errorf("failed to delete group: %v", err)
	}

	c.Logger.Info("group deleted successfully", zap.String("groupName", groupName))
	return nil
}

func (c *Client) AddUserToGroup(groupName string, memberUid string) error {
	in, err := c.userInGroup(groupName, memberUid)
	if err != nil {
		c.Logger.Error("failed to check user in group", zap.String("groupName", groupName), zap.String("memberUid", memberUid), zap.Error(err))
		return fmt.Errorf("failed to check user in group: %w", err)
	}
	if in {
		c.Logger.Warn("user already in group", zap.String("groupName", groupName), zap.String("memberUid", memberUid))
		return fmt.Errorf("%w: %s", ErrUserAlreadyInGroup, memberUid)
	}

	dn := fmt.Sprintf("cn=%s,ou=Groups,%s", groupName, c.Config.LDAPBaseDN)
	modifyRequest := ldap.NewModifyRequest(dn, nil)
	modifyRequest.Add("memberUid", []string{memberUid})

	err = c.Conn.Modify(modifyRequest)
	if err != nil {
		c.Logger.Error("failed to add user to group", zap.String("group_name", groupName), zap.String("user_uid", memberUid), zap.Error(err))
		return fmt.Errorf("failed to add user to group: %v", err)
	}

	c.Logger.Info("user added to group successfully", zap.String("groupName", groupName), zap.String("memberUid", memberUid))
	return nil
}

func (c *Client) RemoveUserFromGroup(groupName string, memberUid string) error {
	in, err := c.userInGroup(groupName, memberUid)
	if err != nil {
		return fmt.Errorf("LDAP search failed: %w", err)
	}
	if !in {
		c.Logger.Warn("user not in group",
			zap.String("cn", groupName), zap.String("memberUid", memberUid))
		return fmt.Errorf("%w: %s", ErrUserNotInGroup, memberUid)
	}

	dn := fmt.Sprintf("cn=%s,ou=Groups,%s", groupName, c.Config.LDAPBaseDN)
	modifyRequest := ldap.NewModifyRequest(dn, nil)
	modifyRequest.Delete("memberUid", []string{memberUid})

	err = c.Conn.Modify(modifyRequest)
	if err != nil {
		c.Logger.Error("failed to remove user from group", zap.String("groupName", groupName), zap.String("memberUid", memberUid), zap.Error(err))
		return fmt.Errorf("failed to remove user from group: %w", err)
	}

	c.Logger.Info("user removed from group successfully", zap.String("groupName", groupName), zap.String("memberUid", memberUid))
	return nil
}

func (c *Client) GetGroupsForUser(uid string) ([]*ldap.Entry, error) {
	userBase := "ou=People," + c.Config.LDAPBaseDN
	userFilter := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(uid))
	exists, err := c.entryExists(userBase, userFilter)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, uid)
	}

	groupBase := "ou=Groups," + c.Config.LDAPBaseDN
	groupFilter := fmt.Sprintf("(memberUid=%s)", ldap.EscapeFilter(uid))
	groupAttributes := []string{"dn", "cn"}
	result, err := c.SearchByFilter(groupBase, groupFilter, groupAttributes)

	if err != nil {
		c.Logger.Error("failed to search groups for user", zap.String("uid", uid), zap.Error(err))
		return nil, fmt.Errorf("failed to search groups for user: %w", err)
	}

	if len(result.Entries) == 0 {
		c.Logger.Warn("user not in any group", zap.String("uid", uid))
		return nil, fmt.Errorf("%w: %s", ErrUserNoGroup, uid)
	}

	return result.Entries, nil
}

func (c *Client) GetAllGIDNumbers() ([]string, error) {
	base := "ou=Groups," + c.Config.LDAPBaseDN
	filter := "(gidNumber=*)"
	attributes := []string{"gidNumber"}

	result, err := c.SearchByFilter(base, filter, attributes)
	if err != nil {
		c.Logger.Error("failed to search for gidNumbers", zap.Error(err))
		return nil, fmt.Errorf("failed to retrieve gidNumbers: %w", err)
	}

	var gidNumbers []string
	for _, entry := range result.Entries {
		gid := entry.GetAttributeValue("gidNumber")
		if gid != "" {
			gidNumbers = append(gidNumbers, gid)
		}
	}

	return gidNumbers, nil
}
