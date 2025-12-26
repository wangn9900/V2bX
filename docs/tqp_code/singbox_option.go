// Package tqp - sing-box option definitions for TQP protocol
//
// Copy this to: sing-box_mod/option/tqp.go
package option

// TQPInboundOptions defines the configuration for TQP inbound
type TQPInboundOptions struct {
	ListenOptions
	Users    []TQPUser           `json:"users,omitempty"`
	TLS      *InboundTLSOptions  `json:"tls,omitempty"`
	Fallback *TQPFallbackOptions `json:"fallback,omitempty"`
}

// TQPUser represents a TQP user
type TQPUser struct {
	Name string `json:"name,omitempty"`
	UUID string `json:"uuid"`
}

// TQPFallbackOptions defines the fallback server for failed auth
type TQPFallbackOptions struct {
	Server     string `json:"server"`
	ServerPort string `json:"server_port"`
}
