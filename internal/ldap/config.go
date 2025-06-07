package ldap

type Config struct {
	Debug       bool   `yaml:"ldap_debug"`
	LDAPHost    string `yaml:"ldap_host"`
	LDAPPort    string `yaml:"ldap_port"`
	LDAPBaseDN  string `yaml:"ldap_base_dn"`
	LDAPBindDN  string `yaml:"ldap_bind_dn"`
	LDAPBindPwd string `yaml:"ldap_bind_pwd"`
}
