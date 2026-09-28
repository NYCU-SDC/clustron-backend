package ansible

import "github.com/google/uuid"

// AllowedLoginGroupSelection identifies which LDAP-backed variant of a Clustron group is
// allowed to log in to a compute node.
type AllowedLoginGroupSelection struct {
	GroupID uuid.UUID
	Type    GroupType
}

// AllowedLoginGroupDetail is an allowed group selection with display information.
type AllowedLoginGroupDetail struct {
	GroupID uuid.UUID
	Type    GroupType
	Title   string
	LdapCN  string
}

// PartitionAllowedGroupDetail is an LDAP variant of a Clustron group allowed to submit jobs to
// a Slurm partition. Its ldap_cn is rendered into that partition's AllowAccounts list: the BASE
// cn is the group's top-level Slurm account (covering its -base and -admin children), the ADMIN
// cn is the -admin child account alone.
type PartitionAllowedGroupDetail struct {
	GroupID uuid.UUID
	Type    GroupType
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
