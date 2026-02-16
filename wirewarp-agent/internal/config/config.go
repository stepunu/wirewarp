package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

const DefaultPath = "/etc/wirewarp/agent.yaml"

type Config struct {
	Mode             string `yaml:"mode"`              // "server" | "client"
	ControlServerURL string `yaml:"control_server_url"`
	AgentToken       string `yaml:"agent_token"`        // registration token (cleared after use)
	AgentJWT         string `yaml:"agent_jwt"`          // JWT issued after registration
	AgentID          string `yaml:"agent_id"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Save(path string) error {
	if err := os.MkdirAll("/etc/wirewarp", 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
