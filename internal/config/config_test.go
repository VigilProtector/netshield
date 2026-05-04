// Package config provides configuration management for NetShield.
package config

import (
	"os"
	"testing"
	"time"
)

// TestLoadConfig tests the LoadConfig function.
func TestLoadConfig(t *testing.T) {
	// This is a basic test to ensure LoadConfig doesn't panic
	// In a real scenario, we would set up environment variables
	// and test various configurations

	// Save current environment
	oldEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, e := range oldEnv {
			parts := splitEnv(e)
			if len(parts) == 2 {
				//nolint:errcheck // Test setup - errors are acceptable in test environment
				os.Setenv(parts[0], parts[1])
			}
		}
	}()

	// Set minimal required environment variables
	//nolint:errcheck // Test setup - errors are acceptable in test environment
	os.Setenv("NETSHIELD_SERVER_PORT", "8900")
	//nolint:errcheck // Test setup - errors are acceptable in test environment
	os.Setenv("NETSHIELD_DATABASE_URI", "mongodb://localhost:27017")
	//nolint:errcheck // Test setup - errors are acceptable in test environment
	os.Setenv("NETSHIELD_DATABASE_NAME", "netshield")
	//nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored
	os.Setenv("NETSHIELD_LOG_LEVEL", "info")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Server.Port != "8900" {
		t.Errorf("Server.Port = %v, want %v", cfg.Server.Port, "8900")
	}
	if cfg.Database.URI != "mongodb://localhost:27017" {
		t.Errorf("Database.URI = %v, want %v", cfg.Database.URI, "mongodb://localhost:27017")
	}
	if cfg.Database.Name != "netshield" {
		t.Errorf("Database.Name = %v, want %v", cfg.Database.Name, "netshield")
	}
}

// splitEnv splits an environment variable string into key and value.
func splitEnv(s string) []string {
	for i, c := range s {
		if c == '=' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

// TestConfigDefaults tests default configuration values.
func TestConfigDefaults(t *testing.T) {
	// Clear environment to test defaults
	oldEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, e := range oldEnv {
			parts := splitEnv(e)
			if len(parts) == 2 {
				//nolint:errcheck // MongoDB cursor or gRPC client Close errors are non-critical and can be ignored
				os.Setenv(parts[0], parts[1])
			}
		}
	}()

	// Load config with defaults
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Check default values
	if cfg.Server.Port != "8900" {
		t.Errorf("Default Server.Port = %v, want %v", cfg.Server.Port, "8900")
	}
	if cfg.Server.ShutdownTimeout != 30*time.Second {
		t.Errorf("Default Server.ShutdownTimeout = %v, want %v", cfg.Server.ShutdownTimeout, 30*time.Second)
	}
	if cfg.LogLevel != 2 {
		t.Errorf("Default LogLevel = %v, want %v", cfg.LogLevel, 2)
	}
}

// TestValidate tests the Validate method of Config.
func TestValidate(t *testing.T) {
	t.Parallel()

	t.Run("valid config", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Server: ServerConfig{
				Port: "8080",
			},
			Environment:  "production",
			LogEncoding: "json",
		}

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("invalid port - non numeric", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Server: ServerConfig{
				Port: "invalid",
			},
			Environment:  "production",
			LogEncoding: "json",
		}

		err := cfg.Validate()
		if err == nil {
			t.Error("Validate() expected error for invalid port, got nil")
		}
		if err != ErrInvalidPort {
			t.Errorf("Validate() error = %v, want %v", err, ErrInvalidPort)
		}
	})

	t.Run("invalid port - below 1024", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Server: ServerConfig{
				Port: "1023",
			},
			Environment:  "production",
			LogEncoding: "json",
		}

		err := cfg.Validate()
		if err == nil {
			t.Error("Validate() expected error for port below 1024, got nil")
		}
		if err != ErrInvalidPort {
			t.Errorf("Validate() error = %v, want %v", err, ErrInvalidPort)
		}
	})

	t.Run("invalid port - above 65535", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Server: ServerConfig{
				Port: "65536",
			},
			Environment:  "production",
			LogEncoding: "json",
		}

		err := cfg.Validate()
		if err == nil {
			t.Error("Validate() expected error for port above 65535, got nil")
		}
		if err != ErrInvalidPort {
			t.Errorf("Validate() error = %v, want %v", err, ErrInvalidPort)
		}
	})

	t.Run("invalid environment", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Server: ServerConfig{
				Port: "8080",
			},
			Environment:  "staging",
			LogEncoding: "json",
		}

		err := cfg.Validate()
		if err == nil {
			t.Error("Validate() expected error for invalid environment, got nil")
		}
		if err != ErrInvalidEnvironment {
			t.Errorf("Validate() error = %v, want %v", err, ErrInvalidEnvironment)
		}
	})

	t.Run("invalid log encoding", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Server: ServerConfig{
				Port: "8080",
			},
			Environment:  "production",
			LogEncoding: "xml",
		}

		err := cfg.Validate()
		if err == nil {
			t.Error("Validate() expected error for invalid log encoding, got nil")
		}
		if err != ErrInvalidLogEncoding {
			t.Errorf("Validate() error = %v, want %v", err, ErrInvalidLogEncoding)
		}
	})

	t.Run("empty port - valid", func(t *testing.T) {
		t.Parallel()

		// Empty port should be valid (validation only happens if Port != "")
		cfg := &Config{
			Server: ServerConfig{
				Port: "",
			},
			Environment:  "production",
			LogEncoding: "json",
		}

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Validate() error = %v, want nil (empty port should be valid)", err)
		}
	})
}
