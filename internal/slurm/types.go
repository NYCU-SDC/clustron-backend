package slurm

type NumberFlag struct {
	Number   int  `json:"number"`
	Set      bool `json:"set"`
	Infinite bool `json:"infinite"`
}

type NumberFlagRequest struct {
	Number int  `json:"number"`
	Set    bool `json:"set"`
}

// SrcError Slurm error format
type SrcError struct {
	Description string `json:"description"`
	Source      string `json:"source"`
	Error       string `json:"error"`
	ErrorNumber int    `json:"error_number"`
}

type ErrorResponse struct {
	Errors []SrcError `json:"errors"`
}

// JobResponse Slurm job response format
type JobResponse struct {
	Account       string     `json:"account"`
	CPUs          NumberFlag `json:"cpus"`
	MemoryPerCPU  NumberFlag `json:"memory_per_cpu"`
	Name          string     `json:"name"`
	Comment       string     `json:"comment"`
	GresDetail    []string   `json:"gres_detail"`
	JobID         int        `json:"job_id"`
	JobState      []string   `json:"job_state"`
	NodeCount     NumberFlag `json:"node_count"`
	Nodes         string     `json:"nodes"`
	Partition     string     `json:"partition"`
	Priority      NumberFlag `json:"priority"`
	QoS           string     `json:"qos"`
	SocketPerNode NumberFlag `json:"socket_per_node"`
	StateReason   string     `json:"state_reason"`
	Tasks         NumberFlag `json:"tasks"`
	TresPerJob    string     `json:"tres_per_job"`
	TresPerNode   string     `json:"tres_per_node"`
	TresPerSocket string     `json:"tres_per_socket"`
	TresPerTask   string     `json:"tres_per_task"`
	Username      string     `json:"user_name"`
}

type JobsResponse struct {
	Jobs []JobResponse `json:"jobs"`
}

func (j JobsResponse) GetStates() [][]string {
	var states [][]string
	for _, job := range j.Jobs {
		states = append(states, job.JobState)
	}
	return states
}

type JobRequest struct {
	Name    string `json:"name" validate:"required"`
	Comment string `json:"comment,omitempty"`
	// CurrentWorkingDirectory required, if not set, use the user's home directory.
	CurrentWorkingDirectory string `json:"current_working_directory,omitempty"`
	Script                  string `json:"script" validate:"required"`
	// Environment Home Directory, Path and Shell are required.
	Environment    []string          `json:"environment,omitempty"`
	Nodes          string            `json:"nodes,omitempty"`
	MaximumNodes   int               `json:"maximum_nodes,omitempty"`
	MinimumNodes   int               `json:"minimum_nodes,omitempty"`
	Tasks          int               `json:"tasks"  validate:"required"`
	CPUsPerTask    int               `json:"cpus_per_task"  validate:"required"`
	MemoryPerCPU   NumberFlagRequest `json:"memory_per_cpu,omitempty"`
	MemoryPerNode  NumberFlagRequest `json:"memory_per_node,omitempty"`
	Partition      string            `json:"partition,omitempty"`
	TimeLimit      NumberFlagRequest `json:"time_limit,omitempty"`
	StandardInput  string            `json:"standard_input,omitempty"`
	StandardOutput string            `json:"standard_output,omitempty"`
	StandardError  string            `json:"standard_error,omitempty"`
}

type SubmitJobRequest struct {
	Job JobRequest `json:"job" validate:"required"`
}

type SrcPartition struct {
	Name string `json:"name"`
}

type PartitionResponse struct {
	Partitions []SrcPartition `json:"partitions"`
}

type JobStateResponse struct {
	Running   int `json:"running"`
	Pending   int `json:"pending"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Timeout   int `json:"timeout"`
	Cancelled int `json:"cancelled"`
	Unknown   int `json:"unknown"`
}

// ignoring meta field in Slurm response
type Response struct {
	Errors   []SlurmError   `json:"errors"`
	Warnings []SlurmWarning `json:"warnings"`
}

type DeleteUserResponse struct {
	RemovedUsers []string       `json:"removed_users"`
	Errors       []SlurmError   `json:"errors"`
	Warnings     []SlurmWarning `json:"warnings"`
}

type DeleteAccountResponse struct {
	RemovedAccounts []string       `json:"removed_accounts"`
	Errors          []SlurmError   `json:"errors"`
	Warnings        []SlurmWarning `json:"warnings"`
}

type DeleteAssociationResponse struct {
	RemovedAssociations []string       `json:"removed_associations"`
	Errors              []SlurmError   `json:"errors"`
	Warnings            []SlurmWarning `json:"warnings"`
}

// User defines the payload required to create a new Slurm user in v0.0.43
type User struct {
	AdministratorLevel []string           `json:"administrator_level,omitempty"`
	Associations       []AssociationShort `json:"associations,omitempty"`
	Default            UserDefault        `json:"default,omitempty"`
	Flags              []string           `json:"flags,omitempty"`
	Name               string             `json:"name" validate:"required"`
}

type Account struct {
	Associations []AssociationShort `json:"associations,omitempty"`
	Coordinators []Coordinator      `json:"coordinators,omitempty"`
	Description  string             `json:"description" validate:"required"`
	Name         string             `json:"name" validate:"required"`
	Organization string             `json:"organization" validate:"required"`
	Flags        []string           `json:"flags,omitempty"`
}

// Association https://slurm.schedmd.com/rest_api.html#slurmdbV0044PostAssociations
type Association struct {
	Account       string   `json:"account,omitempty"`
	Cluster       string   `json:"cluster,omitempty"`
	Comment       string   `json:"comment,omitempty"`
	Flags         string   `json:"flags,omitempty"`
	Id            int32    `json:"id,omitempty"`
	IsDefault     bool     `json:"is_default,omitempty"`
	Lineage       string   `json:"lineage,omitempty"`
	ParentAccount string   `json:"parent_account,omitempty"`
	Partition     string   `json:"partition,omitempty"`
	Qos           []string `json:"qos,omitempty"`
	SharesRaw     int32    `json:"shares_raw,omitempty"`
	User          string   `json:"user" validate:"required"`
}

type UserAssociationRequest struct {
	AssociationCondition UserAddCondition `json:"association_condition" validate:"required"`
	User                 UserShort        `json:"user" validate:"required"`
}

// UserAddCondition https://slurm.schedmd.com/rest_api.html#v0.0.44_openapi_users_add_cond_resp
type UserAddCondition struct {
	Users       []string          `json:"users"`
	Accounts    []string          `json:"accounts,omitempty"`
	Association AssociationRecSet `json:"association,omitempty"`
	Clusters    []string          `json:"clusters,omitempty"`
	Partitions  []string          `json:"partitions,omitempty"`
	Wckeys      []string          `json:"wckeys,omitempty"`
}

// UserShort https://slurm.schedmd.com/rest_api.html#v0.0.44_user_short
type UserShort struct {
	AdminLevel     string `json:"adminlevel,omitempty"`
	DefaultQos     string `json:"defaultqos,omitempty"`
	DefaultAccount string `json:"defaultaccount,omitempty"`
	DefaultWckey   string `json:"defaultwckey,omitempty"`
}

type AccountAssociationRequest struct {
	AssociationCondition AccountAddCondition `json:"association_condition" validate:"required"`
	Account              AccountShort        `json:"account" validate:"required"`
}

// AccountAddCondition https://slurm.schedmd.com/rest_api.html#v0.0.44_accounts_add_cond
type AccountAddCondition struct {
	Accounts    []string          `json:"accounts"`
	Association AssociationRecSet `json:"association"`
	Clusters    []string          `json:"clusters,omitempty"`
}

// AccountShort https://slurm.schedmd.com/rest_api.html#v0.0.44_account_short
type AccountShort struct {
	Description  string `json:"description,omitempty"`
	Organization string `json:"organization,omitempty"`
}

// AssociationRecSet https://slurm.schedmd.com/rest_api.html#v0.0.44_assoc_rec_set
type AssociationRecSet struct {
	Comment               string        `json:"comment,omitempty"`
	DefaultQos            string        `json:"defaultqos,omitempty"`
	Parent                string        `json:"parent,omitempty"`
	MaxWallDurationPerJob Uint32NoValue `json:"maxwalldurationperjob,omitempty"`
	MaxSubmitJobs         Uint32NoValue `json:"maxsubmitjobs,omitempty"`
	MaxJobs               Uint32NoValue `json:"maxjobs,omitempty"`
}

// Uint32NoValue https://slurm.schedmd.com/rest_api.html#v0.0.44_uint32_no_val_struct
type Uint32NoValue struct {
	Set      bool  `json:"set,omitempty"`
	Infinite bool  `json:"infinite,omitempty"`
	Number   int32 `json:"number,omitempty"`
}

// UserRequest expects an array of users for the POST request
type UserRequest struct {
	Users []User `json:"users" validate:"required"`
}

type AccountRequest struct {
	Accounts []Account `json:"accounts" validate:"required"`
}

type AssociationRequest struct {
	Associations []Association `json:"associations" validate:"required"`
}

type AssociationShort struct {
	Account   string `json:"account"`
	Cluster   string `json:"cluster"`
	Partition string `json:"partition,omitempty"`
	User      string `json:"user"`
}

type Coordinator struct {
	Name   string `json:"name"`
	Direct int    `json:"direct"` // 1 if direct, 0 if inherited
}

type UserDefault struct {
	Qos     string `json:"qos"`
	Account string `json:"account"`
	Wckey   string `json:"wckey"`
}

type SlurmError struct {
	Description string `json:"description"`
	ErrorCode   int    `json:"error_number"`
	Source      string `json:"source"`
}

type SlurmWarning struct {
	Description string `json:"description"`
	Source      string `json:"source"`
}
