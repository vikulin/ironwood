package types

import (
	"encoding/hex"
)

// Addr implements the `net.Addr` interface for `Domain` values.
type Addr Domain

// Network returns "Domain.name" as a string.
func (a Addr) Network() string {
	return string(a.Name[:])
}

// String returns the ed25519.PublicKey as a hexidecimal string.
func (a Addr) String() string {
	return hex.EncodeToString(a.Key[:])
}
