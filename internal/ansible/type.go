package ansible

import "github.com/google/uuid"

// AllowedLoginGroupDetail is an LDAP group whose members are allowed to log in to compute
// nodes. Its LDAPGroupID resolves to the ldap_cn rendered in SSSD's simple_allow_groups.
type AllowedLoginGroupDetail struct {
	LDAPGroupID uuid.UUID
	Title       string
	LdapCN      string
}

type InventoryFiles struct {
	All ServerGroup `yaml:"all"`
}
type ServerGroup struct {
	Vars     map[string]interface{} `yaml:"vars,omitempty"`
	Children map[string]ChildNode   `yaml:"children,omitempty"`
}
type ChildNode struct {
	Hosts map[string]HostVars `yaml:"hosts,omitempty"`
}
type HostVars struct {
	HostName              string `yaml:"ansible_host,omitempty"`
	UserName              string `yaml:"ansible_user,omitempty"`
	SSHKeyPath            string `yaml:"ansible_ssh_private_key_file,omitempty"`
	PrivateIP             string `yaml:"private_ip,omitempty"`
	CPUCores              int32  `yaml:"cpu_cores,omitempty"`
	MemoryMB              int32  `yaml:"memory_mb,omitempty"`
	SlurmPartition        string `yaml:"slurm_partition,omitempty"`
	LDAPSimpleAllowGroups string `yaml:"ldap_simple_allow_groups,omitempty"`
}
