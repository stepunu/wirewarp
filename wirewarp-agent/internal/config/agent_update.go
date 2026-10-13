package config

type AgentUpdateReceipt struct {
	OwnerAgentID string `yaml:"owner_agent_id"`
	CommandID    string `yaml:"command_id"`
	ReceiptID    string `yaml:"receipt_id"`
	SHA256       string `yaml:"sha256"`
	Version      string `yaml:"version"`
	Installed    bool   `yaml:"installed"`
	Success      bool   `yaml:"success"`
	Detail       string `yaml:"detail"`
}
