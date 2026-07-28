package slurm

type Config struct {
	SlurmTokenHelperURL    string `yaml:"slurm_token_helper_url"`
	SlurmTokenHelperAPIKey string `yaml:"slurm_token_helper_api_key"`
	SlurmRestfulBaseURL    string `yaml:"slurm_restful_base_url"`
	SlurmRestfulVersion    string `yaml:"slurm_restful_version"`
	SlurmRootToken         string `yaml:"slurm_root_token"`
}
