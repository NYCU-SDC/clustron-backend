package ansible

import "github.com/google/uuid"

// AllowedLoginGroupDetail is a Clustron group whose members are allowed to log in to compute
// nodes. It maps to one entry in SSSD's simple_allow_groups (via the group's BASE ldap_cn).
type AllowedLoginGroupDetail struct {
	GroupID uuid.UUID
	Title   string
	LdapCN  string
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
