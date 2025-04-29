package ldap

type Config struct {
	Debug       bool
	LDAPHost    string
	LDAPPort    string
	LDAPBaseDN  string
	LDAPBindDN  string
	LDAPBindPwd string
}
