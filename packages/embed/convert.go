// Package embed runs the Sub-Store conversion core inside a pure Go JavaScript engine (slowjs).
package embed

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/liustack/slowjs"
)

//go:embed build/bundle.js
var bundle string

// Converter owns one JS VM. It is safe for concurrent use (calls are serialized).
type Converter struct {
	mu sync.Mutex
	vm *slowjs.VM
}

// New creates a Converter and loads the bundled core.
func New() (*Converter, error) {
	vm, err := slowjs.NewVM()
	if err != nil {
		return nil, err
	}
	if _, err := vm.Eval(bundle, slowjs.EvalGlobal); err != nil {
		vm.Close()
		return nil, fmt.Errorf("load bundle: %w", err)
	}
	return &Converter{vm: vm}, nil
}

// Close releases the VM.
func (c *Converter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.vm.Close()
}

// Convert converts raw subscription content (base64, URI list, Clash YAML, ...) to the
// target format (e.g. "clash", "surge", "loon", "qx", "uri"). opts is merged into every
// parsed proxy and may be nil.
func (c *Converter) Convert(raw, target string, opts map[string]any) (string, error) {
	optsJSON := ""
	if len(opts) > 0 {
		b, err := json.Marshal(opts)
		if err != nil {
			return "", err
		}
		optsJSON = string(b)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.vm.Call("SubConvert.convert", raw, target, optsJSON)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("unexpected result type %T", v)
	}
	return s, nil
}

// Convert is a one-shot helper that creates a Converter, converts and closes it.
func Convert(raw, target string, opts map[string]any) (string, error) {
	c, err := New()
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.Convert(raw, target, opts)
}
