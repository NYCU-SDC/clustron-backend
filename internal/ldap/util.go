package ldap

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

func (c *Client) SearchByFilter(baseDN string, filter string, attributes []string) (*ldap.SearchResult, error) {
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)

	result, err := c.Conn.Search(searchReq)
	if err != nil {
		c.Logger.Error("failed to search by filter",
			zap.String("baseDN", baseDN),
			zap.String("filter", filter),
			zap.Error(err))
		return nil, fmt.Errorf("failed to search by filter %s: %w", filter, err)
	}

	return result, nil
}

func (c *Client) entryExists(baseDN, filter string) (bool, error) {
	result, err := c.SearchByFilter(baseDN, filter, []string{"dn"})
	if err != nil {
		c.Logger.Error("failed to check entry existence",
			zap.String("baseDN", baseDN),
			zap.String("filter", filter),
			zap.Error(err))
		return false, fmt.Errorf("failed to check entry existence: %w", err)
	}
	return len(result.Entries) > 0, nil
}

func (c *Client) userInGroup(groupName, uid string) (bool, error) {
	baseDN := fmt.Sprintf("cn=%s,ou=Groups,%s", groupName, c.Config.LDAPBaseDN)
	filter := fmt.Sprintf("(memberUid=%s)", ldap.EscapeFilter(uid))

	result, err := c.SearchByFilter(baseDN, filter, []string{"dn"})
	if err != nil {
		c.Logger.Error("failed to check if user is in group",
			zap.String("groupName", groupName),
			zap.String("uid", uid),
			zap.Error(err))
		return false, fmt.Errorf("failed to check if user is in group: %w", err)
	}
	return len(result.Entries) > 0, nil
}
