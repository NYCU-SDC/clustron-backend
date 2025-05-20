package config

import (
	"errors"
	"flag"
	configutil "github.com/NYCU-SDC/summer/pkg/config"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	"os"
)

const DefaultSecret = "default-secret"

var ErrDatabaseURLRequired = errors.New("database_url is required")

type PresetUserInfo struct {
	Role string `yaml:"role"`
}

type Config struct {
	Debug                   bool                      `yaml:"debug"              envconfig:"DEBUG"`
	Host                    string                    `yaml:"host"               envconfig:"HOST"`
	Port                    string                    `yaml:"port"               envconfig:"PORT"`
	BaseURL                 string                    `yaml:"base_url"          envconfig:"BASE_URL"`
	Secret                  string                    `yaml:"secret"             envconfig:"SECRET"`
	DatabaseURL             string                    `yaml:"database_url"       envconfig:"DATABASE_URL"`
	MigrationSource         string                    `yaml:"migration_source"   envconfig:"MIGRATION_SOURCE"`
	OtelCollectorUrl        string                    `yaml:"otel_collector_url" envconfig:"OTEL_COLLECTOR_URL"`
	GoogleOauthClientID     string                    `yaml:"google_oauth_client_id"    envconfig:"GOOGLE_OAUTH_CLIENT_ID"`
	GoogleOauthClientSecret string                    `yaml:"google_oauth_client_secret" envconfig:"GOOGLE_OAUTH_CLIENT_SECRET"`
	NYCUOauthClientID       string                    `yaml:"nycu_oauth_client_id"    envconfig:"NYCU_OAUTH_CLIENT_ID"`
	NYCUOauthClientSecret   string                    `yaml:"nycu_oauth_client_secret" envconfig:"NYCU_OAUTH_CLIENT_SECRET"`
	PresetUser              map[string]PresetUserInfo `yaml:"preset_user"`
}

type LogBuffer struct {
	buffer []logEntry
}

type logEntry struct {
	msg  string
	err  error
	meta map[string]string
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
		OtelCollectorUrl:        "",
		GoogleOauthClientID:     "",
		GoogleOauthClientSecret: "",
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

	envConfig := &Config{
		Debug:                   os.Getenv("DEBUG") == "true",
		Host:                    os.Getenv("HOST"),
		Port:                    os.Getenv("PORT"),
		BaseURL:                 os.Getenv("BASE_URL"),
		Secret:                  os.Getenv("SECRET"),
		DatabaseURL:             os.Getenv("DATABASE_URL"),
		MigrationSource:         os.Getenv("MIGRATION_SOURCE"),
		OtelCollectorUrl:        os.Getenv("OTEL_COLLECTOR_URL"),
		GoogleOauthClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		GoogleOauthClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		NYCUOauthClientID:       os.Getenv("NYCU_OAUTH_CLIENT_ID"),
		NYCUOauthClientSecret:   os.Getenv("NYCU_OAUTH_CLIENT_SECRET"),
	}

	return configutil.Merge[Config](config, envConfig)
}

func FromFlags(config *Config) (*Config, error) {
	flagConfig := &Config{}

	flag.BoolVar(&flagConfig.Debug, "debug", false, "debug mode")
	flag.StringVar(&flagConfig.Host, "host", "", "host")
	flag.StringVar(&flagConfig.Port, "port", "", "port")
	flag.StringVar(&flagConfig.BaseURL, "base_url", "", "base url")
	flag.StringVar(&flagConfig.Secret, "secret", "", "secret")
	flag.StringVar(&flagConfig.DatabaseURL, "database_url", "", "database url")
	flag.StringVar(&flagConfig.MigrationSource, "migration_source", "", "migration source")
	flag.StringVar(&flagConfig.OtelCollectorUrl, "otel_collector_url", "", "OpenTelemetry collector URL")
	flag.StringVar(&flagConfig.GoogleOauthClientID, "google_oauth_client_id", "", "OAuth client ID")
	flag.StringVar(&flagConfig.GoogleOauthClientSecret, "google_oauth_client_secret", "", "OAuth client secret")
	flag.StringVar(&flagConfig.NYCUOauthClientID, "nycu_oauth_client_id", "", "NYCU OAuth client ID")
	flag.StringVar(&flagConfig.NYCUOauthClientSecret, "nycu_oauth_client_secret", "", "NYCU OAuth client secret")

	flag.Parse()

	return configutil.Merge[Config](config, flagConfig)
}
