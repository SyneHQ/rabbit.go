package server

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
	"rabbit.go/internal/middleware"
)

// OperatorConfig contains limits only. Credentials remain in their existing secret inputs.
type OperatorConfig struct {
	Security             middleware.SecurityConfig `yaml:"security"`
	PairingTimeout       time.Duration             `yaml:"pairing_timeout"`
	ControlWriteTimeout  time.Duration             `yaml:"control_write_timeout"`
	AuditQueueCapacity   int                       `yaml:"audit_queue_capacity"`
	AuditWriteTimeout    time.Duration             `yaml:"audit_write_timeout"`
	AuditShutdownTimeout time.Duration             `yaml:"audit_shutdown_timeout"`
}

func LoadOperatorConfig(path string) (OperatorConfig, error) {
	config := OperatorConfig{Security: middleware.DefaultSecurityConfig(), PairingTimeout: 10 * time.Second, ControlWriteTimeout: controlWriteTimeout, AuditQueueCapacity: 1024, AuditWriteTimeout: 5 * time.Second, AuditShutdownTimeout: 5 * time.Second}
	if path != "" {
		file, err := openOperatorFile(path)
		if err != nil {
			return config, fmt.Errorf("open operator configuration: %w", err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
			return config, fmt.Errorf("operator configuration must be a regular file no larger than 64 KiB")
		}
		decoder := yaml.NewDecoder(io.LimitReader(file, 64<<10+1))
		decoder.KnownFields(true)
		if err := decoder.Decode(&config); err != nil {
			return config, fmt.Errorf("invalid operator YAML: %w", err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return config, fmt.Errorf("operator configuration must contain one YAML document")
		}
	}
	var err error
	config.Security, err = middleware.ApplySecurityEnv(config.Security)
	if err != nil {
		return config, err
	}
	for _, setting := range []struct {
		name   string
		target *time.Duration
	}{{"RABBIT_PAIRING_TIMEOUT", &config.PairingTimeout}, {"RABBIT_CONTROL_WRITE_TIMEOUT", &config.ControlWriteTimeout}} {
		if value, exists := os.LookupEnv(setting.name); exists {
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return config, fmt.Errorf("%s must be a duration such as 10s", setting.name)
			}
			*setting.target = parsed
		}
		if *setting.target < time.Millisecond || *setting.target > time.Minute {
			return config, fmt.Errorf("%s must be between 1ms and 1m", setting.name)
		}
	}
	if value, exists := os.LookupEnv("RABBIT_AUDIT_QUEUE_CAPACITY"); exists {
		parsed, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(parsed) != value {
			return config, fmt.Errorf("RABBIT_AUDIT_QUEUE_CAPACITY must be an integer")
		}
		config.AuditQueueCapacity = parsed
	}
	if config.AuditQueueCapacity < 0 || config.AuditQueueCapacity > 65536 {
		return config, fmt.Errorf("audit_queue_capacity must be between 0 and 65536")
	}
	for _, setting := range []struct {
		name   string
		target *time.Duration
	}{{"RABBIT_AUDIT_WRITE_TIMEOUT", &config.AuditWriteTimeout}, {"RABBIT_AUDIT_SHUTDOWN_TIMEOUT", &config.AuditShutdownTimeout}} {
		if value, exists := os.LookupEnv(setting.name); exists {
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return config, fmt.Errorf("%s must be a duration", setting.name)
			}
			*setting.target = parsed
		}
		if *setting.target < time.Millisecond || *setting.target > time.Minute {
			return config, fmt.Errorf("%s must be between 1ms and 1m", setting.name)
		}
	}
	return config, nil
}

func (s *Server) pairingTimeout() time.Duration {
	if s.operator.PairingTimeout > 0 {
		return s.operator.PairingTimeout
	}
	return 10 * time.Second
}
func (s *Server) controlTimeout() time.Duration {
	if s.operator.ControlWriteTimeout > 0 {
		return s.operator.ControlWriteTimeout
	}
	return controlWriteTimeout
}

func (s *Server) handshakeTimeout() time.Duration {
	if s.operator.Security.HandshakeTimeout > 0 {
		return s.operator.Security.HandshakeTimeout
	}
	return 10 * time.Second
}
