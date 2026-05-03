// Package config provides configuration loading and validation for NetShield service.
package config

import (
	"errors"
	"strconv"
	"time"

	"vigilprotector.io/vp-lib/config"
)

const (
	// DefaultLogLevel is the default logging level.
	DefaultLogLevel = 2 // LogLevelInfo

	// DefaultServerPort is the default HTTP API port.
	DefaultServerPort = "8900"

	// DefaultMetricsPort is the default metrics/health port.
	DefaultMetricsPort = "9090"

	// DefaultShutdownTimeout is the default server shutdown timeout.
	DefaultShutdownTimeout = 30 * time.Second
)

// Errors for configuration validation.
var (
	ErrInvalidPort        = errors.New("server port must be between 1024 and 65535")
	ErrInvalidEnvironment = errors.New("ENVIRONMENT must be 'production' or 'development'")
	ErrInvalidLogEncoding = errors.New("LOG_ENCODING must be 'json' or 'console'")
)

// Config holds the application configuration.
type Config struct {
	Server      ServerConfig
	Metrics     MetricsConfig
	Database    DatabaseConfig
	FlowSeeker  FlowSeekerConfig
	Aegis       AegisConfig
	NetSentinel NetSentinelConfig
	NetAtlas    NetAtlasConfig
	Environment string
	LogLevel    int8
	LogEncoding string
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Port            string
	ShutdownTimeout time.Duration
}

// MetricsConfig holds metrics server configuration.
type MetricsConfig struct {
	Port string
}

// DatabaseConfig holds MongoDB configuration.
type DatabaseConfig struct {
	URI         string
	Name        string
	Timeout     time.Duration
	MaxPool     int
	MinPool     int
	IdleTimeout time.Duration
}

// FlowSeekerConfig holds FlowSeeker subscription configuration.
type FlowSeekerConfig struct {
	// BaseURL is the FlowSeeker subscription endpoint root URL.
	BaseURL string
	// PollInterval is the interval between polls for new findings.
	PollInterval time.Duration
	// BatchSize is the number of findings to fetch per request.
	BatchSize int
}

// AegisConfig holds Aegis service configuration for cross-BC queries.
type AegisConfig struct {
	// BaseURL is the Aegis API root URL.
	BaseURL string
	// Timeout is the HTTP client timeout.
	Timeout time.Duration
}

// NetSentinelConfig holds NetSentinel service configuration for cross-BC queries.
type NetSentinelConfig struct {
	// BaseURL is the NetSentinel Query-Fassade API root URL.
	BaseURL string
	// Timeout is the HTTP client timeout.
	Timeout time.Duration
}

// NetAtlasConfig holds NetAtlas service configuration for cross-BC queries.
type NetAtlasConfig struct {
	// BaseURL is the NetAtlas API root URL.
	BaseURL string
	// Timeout is the HTTP client timeout.
	Timeout time.Duration
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port:            config.GetEnvOrDefault("SERVER_PORT", DefaultServerPort),
			ShutdownTimeout: DefaultShutdownTimeout,
		},
		Metrics: MetricsConfig{
			Port: config.GetEnvOrDefault("METRICS_PORT", DefaultMetricsPort),
		},
		Database: DatabaseConfig{
			URI:         config.GetEnvOrDefault("MONGODB_URI", "mongodb://localhost:27017"),
			Name:        config.GetEnvOrDefault("MONGODB_DATABASE", "netshield"),
			Timeout:     config.ParseDurationOrDefault("MONGODB_TIMEOUT", "5s"),
			MaxPool:     config.ParseIntOrDefault("MONGODB_MAX_POOL", 100),
			MinPool:     config.ParseIntOrDefault("MONGODB_MIN_POOL", 5),
			IdleTimeout: config.ParseDurationOrDefault("MONGODB_IDLE_TIMEOUT", "30s"),
		},
		FlowSeeker: FlowSeekerConfig{
			BaseURL:      config.GetEnvOrDefault("FLOWSEEKER_BASE_URL", ""),
			PollInterval: config.ParseDurationOrDefault("FLOWSEEKER_POLL_INTERVAL", "5s"),
			BatchSize:    config.ParseIntOrDefault("FLOWSEEKER_BATCH_SIZE", 100),
		},
		Aegis: AegisConfig{
			BaseURL: config.GetEnvOrDefault("AEGIS_BASE_URL", ""),
			Timeout: config.ParseDurationOrDefault("AEGIS_TIMEOUT", "10s"),
		},
		NetSentinel: NetSentinelConfig{
			BaseURL: config.GetEnvOrDefault("NETSENTINEL_BASE_URL", ""),
			Timeout: config.ParseDurationOrDefault("NETSENTINEL_TIMEOUT", "10s"),
		},
		NetAtlas: NetAtlasConfig{
			BaseURL: config.GetEnvOrDefault("NETATLAS_BASE_URL", ""),
			Timeout: config.ParseDurationOrDefault("NETATLAS_TIMEOUT", "10s"),
		},
		Environment: config.GetEnvOrDefault("ENVIRONMENT", "production"),
		LogLevel:    config.ParseInt8OrDefault("LOG_LEVEL", DefaultLogLevel),
		LogEncoding: config.GetEnvOrDefault("LOG_ENCODING", "json"),
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate server port
	if c.Server.Port != "" {
		intPort, err := strconv.Atoi(c.Server.Port)
		if err != nil || intPort <= 1024 || intPort > 65535 {
			return ErrInvalidPort
		}
	}

	// Validate environment
	if c.Environment != "production" && c.Environment != "development" {
		return ErrInvalidEnvironment
	}

	// Validate log encoding
	if c.LogEncoding != "json" && c.LogEncoding != "console" {
		return ErrInvalidLogEncoding
	}

	return nil
}
