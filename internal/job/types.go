package job

import "clustron-backend/internal/slurm"

type Request struct {
	Name                    string   `json:"name" validate:"required"`
	Comment                 string   `json:"comment"`
	CurrentWorkingDirectory string   `json:"current_working_directory"`
	Script                  string   `json:"script" validate:"required"`
	Environment             []string `json:"environment"`
	Nodes                   string   `json:"nodes"`
	MaximumNodes            int      `json:"maximum_nodes"`
	MinimumNodes            int      `json:"minimum_nodes"`
	Tasks                   int      `json:"tasks" validate:"required"`
	CPUsPerTask             int      `json:"cpus_per_task" validate:"required"`
	MemoryPerCPU            int      `json:"memory_per_cpu"`
	MemoryPerNode           int      `json:"memory_per_node"`
	Partition               string   `json:"partition"`
	TimeLimit               int      `json:"time_limit"`
	StandardInput           string   `json:"standard_input"`
	StandardOutput          string   `json:"standard_output"`
	StandardError           string   `json:"standard_error"`
}

func (r Request) ToSlurmJobRequest() slurm.JobRequest {
	return slurm.JobRequest{
		Name:                    r.Name,
		Comment:                 r.Comment,
		CurrentWorkingDirectory: r.CurrentWorkingDirectory,
		Script:                  r.Script,
		Environment:             r.Environment,
		Nodes:                   r.Nodes,
		MaximumNodes:            r.MaximumNodes,
		MinimumNodes:            r.MinimumNodes,
		Tasks:                   r.Tasks,
		CPUsPerTask:             r.CPUsPerTask,
		MemoryPerCPU: slurm.NumberFlagRequest{
			Number: r.MemoryPerCPU,
			Set:    r.MemoryPerCPU != 0,
		},
		MemoryPerNode: slurm.NumberFlagRequest{
			Number: r.MemoryPerNode,
			Set:    r.MemoryPerNode != 0,
		},
		Partition: r.Partition,
		TimeLimit: slurm.NumberFlagRequest{
			Number: r.TimeLimit,
			Set:    r.TimeLimit != 0,
		},
		StandardInput:  r.StandardInput,
		StandardOutput: r.StandardOutput,
		StandardError:  r.StandardError,
	}
}

type PartitionsResponse struct {
	Partitions []string `json:"partitions"`
}
