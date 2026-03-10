package config

import (
	"clustron-backend/internal/ldap"
	"clustron-backend/internal/user/role"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"

	configutil "github.com/NYCU-SDC/summer/pkg/config"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const DefaultSecret = "default-secret"

var (
	ErrDatabaseURLRequired         = errors.New("database_url is required")
	ErrInvalidUserRole             = errors.New("invalid user role")
	ErrSlurmRestfulURLRequired     = errors.New("slurm_restful_base_url is required")
	ErrSlurmTokenHelperURLRequired = errors.New("slurm_token_helper_url is required")
)

type PresetUserInfo struct {
	Role string `yaml:"role"`
}

type Config struct {
	Debug                   bool                      `yaml:"debug"              envconfig:"DEBUG"`
	Host                    string                    `yaml:"host"               envconfig:"HOST"`
	Port                    string                    `yaml:"port"               envconfig:"PORT"`
	BaseURL                 string                    `yaml:"base_url"          envconfig:"BASE_URL"`
	OAuthProxyBaseURL       string                    `yaml:"oauth_proxy_base_url" envconfig:"OAUTH_PROXY_BASE_URL"`
	OAuthProxySecret        string                    `yaml:"oauth_proxy_secret" envconfig:"OAUTH_PROXY_SECRET"`
	Secret                  string                    `yaml:"secret"             envconfig:"SECRET"`
	DatabaseURL             string                    `yaml:"database_url"       envconfig:"DATABASE_URL"`
	SlurmTokenHelperURL     string                    `yaml:"slurm_token_helper_url"          envconfig:"SLURM_TOKEN_HELPER_URL"`
	SlurmRestfulBaseURL     string                    `yaml:"slurm_restful_base_url"          envconfig:"SLURM_RESTFUL_BASE_URL"`
	SlurmRestfulVersion     string                    `yaml:"slurm_restful_version"          envconfig:"SLURM_RESTFUL_VERSION"`
	MigrationSource         string                    `yaml:"migration_source"   envconfig:"MIGRATION_SOURCE"`
	CasbinPolicySource      string                    `yaml:"casbin_policy_source" envconfig:"CASBIN_POLICY_SOURCE"`
	CasbinModelSource       string                    `yaml:"casbin_model_source"   envconfig:"CASBIN_MODEL_SOURCE"`
	RedisURL                string                    `yaml:"redis_url"          envconfig:"REDIS_URL"`
	OtelCollectorUrl        string                    `yaml:"otel_collector_url" envconfig:"OTEL_COLLECTOR_URL"`
	GoogleOauthClientID     string                    `yaml:"google_oauth_client_id"    envconfig:"GOOGLE_OAUTH_CLIENT_ID"`
	GoogleOauthClientSecret string                    `yaml:"google_oauth_client_secret" envconfig:"GOOGLE_OAUTH_CLIENT_SECRET"`
	GithubOauthClientID     string                    `yaml:"github_oauth_client_id"    envconfig:"GITHUB_OAUTH_CLIENT_ID"`
	GithubOauthClientSecret string                    `yaml:"github_oauth_client_secret" envconfig:"GITHUB_OAUTH_CLIENT_SECRET"`
	NYCUOauthClientID       string                    `yaml:"nycu_oauth_client_id"    envconfig:"NYCU_OAUTH_CLIENT_ID"`
	NYCUOauthClientSecret   string                    `yaml:"nycu_oauth_client_secret" envconfig:"NYCU_OAUTH_CLIENT_SECRET"`
	AllowOrigins            []string                  `yaml:"allow_origins"      envconfig:"ALLOW_ORIGINS"`
	PresetUser              map[string]PresetUserInfo `yaml:"preset_user"`
	LDAP                    ldap.Config               `yaml:"ldap"`
}

type LogBuffer struct {
	buffer []logEntry
}

type logEntry struct {
	msg  string
	err  error
	meta map[string]string
}

type PresetUserJson struct {
	User string `json:"user"`
	Role string `json:"role"`
}

func NewConfigLogger() *LogBuffer {
	return &LogBuffer{}
}

func (cl *LogBuffer) Warn(msg string, err error, meta map[string]string) {
	cl.buffer = append(cl.buffer, logEntry{msg: msg, err: err, meta: meta})
}

func (cl *LogBuffer) FlushToZap(logger *zap.Logger) {
	for _, e := range cl.buffer {
		var fields []zap.Field
		if e.err != nil {
			fields = append(fields, zap.Error(e.err))
		}
		for k, v := range e.meta {
			fields = append(fields, zap.String(k, v))
		}
		logger.Warn(e.msg, fields...)
	}
	cl.buffer = nil
}

func (c *Config) Validate() error {
	if c.DatabaseURL == "" {
		return ErrDatabaseURLRequired
	}

	for _, user := range c.PresetUser {
		if !role.IsValidGlobalRole(user.Role) {
			return ErrInvalidUserRole
		}
	}

	if c.SlurmRestfulBaseURL == "" {
		return ErrSlurmRestfulURLRequired
	}

	if c.SlurmTokenHelperURL == "" {
		return ErrSlurmTokenHelperURLRequired
	}

	return nil
}

func Load() (Config, *LogBuffer) {
	logger := NewConfigLogger()

	config := &Config{
		Debug:                   false,
		Host:                    "localhost",
		Port:                    "8080",
		Secret:                  DefaultSecret,
		DatabaseURL:             "",
		MigrationSource:         "file://internal/database/migrations",
		CasbinPolicySource:      "internal/casbin/full_policy.csv",
		CasbinModelSource:       "internal/casbin/model.conf",
		OtelCollectorUrl:        "",
		GoogleOauthClientID:     "",
		GoogleOauthClientSecret: "",
		GithubOauthClientID:     "",
		GithubOauthClientSecret: "",
	}

	var err error

	config, err = FromFile("config.yaml", config, logger)
	if err != nil {
		logger.Warn("Failed to load config from file", err, map[string]string{"path": "config.yaml"})
	}

	config, err = FromEnv(config, logger)
	if err != nil {
		logger.Warn("Failed to load config from env", err, map[string]string{"path": ".env"})
	}

	config, err = FromFlags(config)
	if err != nil {
		logger.Warn("Failed to load config from flags", err, map[string]string{"path": "flags"})
	}

	return *config, logger
}

func FromFile(filePath string, config *Config, logger *LogBuffer) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return config, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			logger.Warn("Failed to close config file", err, map[string]string{"path": filePath})
		}
	}(file)

	fileConfig := Config{}
	if err := yaml.NewDecoder(file).Decode(&fileConfig); err != nil {
		return config, err
	}

	return configutil.Merge[Config](config, &fileConfig)
}

func FromEnv(config *Config, logger *LogBuffer) (*Config, error) {
	if err := godotenv.Overload(); err != nil {
		if os.IsNotExist(err) {
			logger.Warn("No .env file found", err, map[string]string{"path": ".env"})
		} else {
			return nil, err
		}
	}

	// parse the preset user config from environment variable
	var res []PresetUserJson
	config.PresetUser = make(map[string]PresetUserInfo)

	presetUserString := os.Getenv("PRESET_USER") // encode with base64

	if presetUserString != "" {
		decodeString, err := base64.StdEncoding.DecodeString(presetUserString)
		if err != nil {
			logger.Warn("Failed to decode PRESET_USER", err, map[string]string{"preset_user": presetUserString})
			return config, err
		}
		err = json.Unmarshal(decodeString, &res)
		if err != nil {
			logger.Warn("Failed to unmarshal PRESET_USER", err, map[string]string{"preset_user": presetUserString})
			return config, err
		}

		for _, user := range res {
			if !role.IsValidGlobalRole(user.Role) {
				logger.Warn("Invalid user role in PRESET_USER", ErrInvalidUserRole, map[string]string{"user": user.User, "role": user.Role})
				return config, ErrInvalidUserRole
			}
			config.PresetUser[user.User] = PresetUserInfo{Role: user.Role}
		}
	}

	// Allow origins
	allowOrigins := os.Getenv("ALLOW_ORIGINS")
	if allowOrigins != "" {
		config.AllowOrigins = strings.Split(allowOrigins, ",")
	}

	envConfig := &Config{
		Debug:                   os.Getenv("DEBUG") == "true",
		Host:                    os.Getenv("HOST"),
		Port:                    os.Getenv("PORT"),
		BaseURL:                 os.Getenv("BASE_URL"),
		OAuthProxyBaseURL:       os.Getenv("OAUTH_PROXY_BASE_URL"),
		OAuthProxySecret:        os.Getenv("OAUTH_PROXY_SECRET"),
		Secret:                  os.Getenv("SECRET"),
		DatabaseURL:             os.Getenv("DATABASE_URL"),
		SlurmTokenHelperURL:     os.Getenv("SLURM_TOKEN_HELPER_URL"),
		SlurmRestfulBaseURL:     os.Getenv("SLURM_RESTFUL_BASE_URL"),
		SlurmRestfulVersion:     os.Getenv("SLURM_RESTFUL_VERSION"),
		MigrationSource:         os.Getenv("MIGRATION_SOURCE"),
		CasbinPolicySource:      os.Getenv("CASBIN_POLICY_SOURCE"),
		CasbinModelSource:       os.Getenv("CASBIN_MODEL_SOURCE"),
		RedisURL:                os.Getenv("REDIS_URL"),
		OtelCollectorUrl:        os.Getenv("OTEL_COLLECTOR_URL"),
		GoogleOauthClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		GoogleOauthClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		GithubOauthClientID:     os.Getenv("GITHUB_OAUTH_CLIENT_ID"),
		GithubOauthClientSecret: os.Getenv("GITHUB_OAUTH_CLIENT_SECRET"),
		NYCUOauthClientID:       os.Getenv("NYCU_OAUTH_CLIENT_ID"),
		NYCUOauthClientSecret:   os.Getenv("NYCU_OAUTH_CLIENT_SECRET"),
		LDAP: ldap.Config{
			Debug:       os.Getenv("LDAP_DEBUG") == "true",
			LDAPHost:    os.Getenv("LDAP_HOST"),
			LDAPPort:    os.Getenv("LDAP_PORT"),
			LDAPBaseDN:  os.Getenv("LDAP_BASE_DN"),
			LDAPBindDN:  os.Getenv("LDAP_BIND_DN"),
			LDAPBindPwd: os.Getenv("LDAP_BIND_PWD"),
		},
	}

	return configutil.Merge[Config](config, envConfig)
}

func FromFlags(config *Config) (*Config, error) {
	flagConfig := &Config{}

	flag.BoolVar(&flagConfig.Debug, "debug", false, "debug mode")
	flag.StringVar(&flagConfig.Host, "host", "", "host")
	flag.StringVar(&flagConfig.Port, "port", "", "port")
	flag.StringVar(&flagConfig.BaseURL, "base_url", "", "base url")
	flag.StringVar(&flagConfig.OAuthProxyBaseURL, "oauth_proxy_base_url", "", "OAuth proxy base url")
	flag.StringVar(&flagConfig.OAuthProxySecret, "oauth_proxy_secret", "", "OAuth proxy secret")
	flag.StringVar(&flagConfig.Secret, "secret", "", "secret")
	flag.StringVar(&flagConfig.DatabaseURL, "database_url", "", "database url")
	flag.StringVar(&flagConfig.SlurmTokenHelperURL, "slurm_token_helper_url", "", "slurm token helper url")
	flag.StringVar(&flagConfig.SlurmRestfulBaseURL, "slurm_restful_base_url", "", "slurm restful base url")
	flag.StringVar(&flagConfig.SlurmRestfulVersion, "slurm_restful_version", "", "slurm restful version")
	flag.StringVar(&flagConfig.MigrationSource, "migration_source", "", "migration source")
	flag.StringVar(&flagConfig.CasbinPolicySource, "casbin_policy_source", "", "casbin policy source")
	flag.StringVar(&flagConfig.CasbinModelSource, "casbin_model_source", "", "casbin model source")
	flag.StringVar(&flagConfig.RedisURL, "redis_url", "", "redis url")
	flag.StringVar(&flagConfig.OtelCollectorUrl, "otel_collector_url", "", "OpenTelemetry collector URL")
	flag.StringVar(&flagConfig.GoogleOauthClientID, "google_oauth_client_id", "", "google OAuth client ID")
	flag.StringVar(&flagConfig.GoogleOauthClientSecret, "google_oauth_client_secret", "", "google OAuth client secret")
	flag.StringVar(&flagConfig.GithubOauthClientID, "github_oauth_client_id", "", "github OAuth client ID")
	flag.StringVar(&flagConfig.GithubOauthClientSecret, "github_oauth_client_secret", "", "github OAuth client secret")
	flag.StringVar(&flagConfig.NYCUOauthClientID, "nycu_oauth_client_id", "", "NYCU OAuth client ID")
	flag.StringVar(&flagConfig.NYCUOauthClientSecret, "nycu_oauth_client_secret", "", "NYCU OAuth client secret")

	flag.Parse()

	return configutil.Merge[Config](config, flagConfig)
}
