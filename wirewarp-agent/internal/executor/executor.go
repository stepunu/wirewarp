package executor

import (
	"encoding/json"
	"fmt"
	"log"
)

// Command is a message received from the control server.
type Command struct {
	ID     string          `json:"id"`
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params"`
}

// Result is sent back to the control server after executing a command.
type Result struct {
	CommandID string `json:"command_id"`
	Type      string `json:"type"`
	Success   bool   `json:"success"`
	Output    string `json:"output"`
	ReceiptID string `json:"receipt_id,omitempty"`
}

// Handler is a function that executes a command and returns output or an error.
type Handler func(params json.RawMessage) (string, error)

// Executor dispatches incoming commands to registered handlers.
type Executor struct {
	handlers        map[string]Handler
	commandHandlers map[string]func(Command) (Result, error)
	send            func(Result) error
}

func New(send func(Result) error) *Executor {
	return &Executor{
		handlers:        make(map[string]Handler),
		commandHandlers: make(map[string]func(Command) (Result, error)),
		send:            send,
	}
}

func (e *Executor) RegisterCommand(commandType string, h func(Command) (Result, error)) {
	e.commandHandlers[commandType] = h
}

func (e *Executor) Register(commandType string, h Handler) {
	e.handlers[commandType] = h
}

func (e *Executor) Dispatch(cmd Command) {
	if h, ok := e.commandHandlers[cmd.Type]; ok {
		result, err := h(cmd)
		result.CommandID = cmd.ID
		result.Type = "command_result"
		result.Success = err == nil
		if err != nil {
			result.Output = err.Error()
		}
		if sendErr := e.send(result); sendErr != nil {
			log.Printf("[executor] failed to send result for command %s: %v", cmd.ID, sendErr)
		}
		return
	}
	h, ok := e.handlers[cmd.Type]
	if !ok {
		log.Printf("[executor] unknown command type: %s (id=%s)", cmd.Type, cmd.ID)
		_ = e.send(Result{
			CommandID: cmd.ID,
			Type:      "command_result",
			Success:   false,
			Output:    fmt.Sprintf("unknown command type: %s", cmd.Type),
		})
		return
	}

	output, err := h(cmd.Params)
	result := Result{
		CommandID: cmd.ID,
		Type:      "command_result",
		Success:   err == nil,
		Output:    output,
	}
	if err != nil {
		result.Output = err.Error()
		log.Printf("[executor] command %s (id=%s) failed: %v", cmd.Type, cmd.ID, err)
	} else {
		log.Printf("[executor] command %s (id=%s) succeeded", cmd.Type, cmd.ID)
	}

	if sendErr := e.send(result); sendErr != nil {
		log.Printf("[executor] failed to send result for command %s: %v", cmd.ID, sendErr)
	}
}
