package ldap

import "strings"

type Config struct {
	Debug            bool   `yaml:"ldap_debug"`
	LDAPHost         string `yaml:"ldap_host"`
	LDAPExternalHost string `yaml:"ldap_external_host"`
	LDAPPort         string `yaml:"ldap_port"`
	LDAPExternalPort string `yaml:"ldap_external_port"`
	// LDAPExternalScheme is the URI scheme cluster nodes use to reach LDAP.
	// Defaults to ldaps; the backend itself always talks plain ldap over the
	// internal network.
	LDAPExternalScheme string `yaml:"ldap_external_scheme"`
	// LDAPCACertFile is a CA certificate readable by the backend that managed
	// nodes must trust to verify the LDAP server. Empty means nodes encrypt the
	// connection without authenticating the server.
	LDAPCACertFile  string `yaml:"ldap_ca_cert_file"`
	LDAPBaseDN      string `yaml:"ldap_base_dn"`
	LDAPUserOUName  string `yaml:"ldap_user_ou_name"`
	LDAPGroupOUName string `yaml:"ldap_group_ou_name"`
	LDAPBindDN      string `yaml:"ldap_bind_dn"`
	LDAPBindPwd     string `yaml:"ldap_bind_pwd"`
}

const (
	SchemeLDAPS      = "ldaps"
	defaultLDAPSPort = "636"
)

// ExternalScheme is the normalized scheme nodes use to reach LDAP.
func (c Config) ExternalScheme() string {
	if c.LDAPExternalScheme == "" {
		return SchemeLDAPS
	}
	return strings.ToLower(c.LDAPExternalScheme)
}

// ExternalPort falls back to the backend's own port only when nodes speak the
// same plaintext scheme.
func (c Config) ExternalPort() string {
	if c.LDAPExternalPort != "" {
		return c.LDAPExternalPort
	}
	if c.ExternalScheme() == SchemeLDAPS {
		return defaultLDAPSPort
	}
	return c.LDAPPort
}
