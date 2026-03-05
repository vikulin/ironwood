package network

import (
	"crypto/ed25519"
	"testing"

	"github.com/Arceliar/ironwood/types"
)

func TestSign(t *testing.T) {
	var c types.Crypto
	_, priv, _ := ed25519.GenerateKey(nil)
	d := types.Domain{}
	c.Init(priv, d)
	msg := []byte("this is a test")
	_ = c.PrivateKey.Sign(msg)
}

func TestVerify(t *testing.T) {
	var c types.Crypto
	pub, priv, _ := ed25519.GenerateKey(nil)
	d := types.NewDomain("verify", pub)
	c.Init(priv, d)
	msg := []byte("this is a test")
	sig := c.PrivateKey.Sign(msg)
	if !c.Domain.Verify(msg, &sig) {
		panic("verification failed")
	}
}

func BenchmarkSign(b *testing.B) {
	var c types.Crypto
	_, priv, _ := ed25519.GenerateKey(nil)
	d := types.Domain{}
	c.Init(priv, d)
	msg := []byte("this is a test")
	for idx := 0; idx < b.N; idx++ {
		_ = c.PrivateKey.Sign(msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	var c types.Crypto
	pub, priv, _ := ed25519.GenerateKey(nil)
	d := types.NewDomain("verify", pub)
	c.Init(priv, d)
	msg := []byte("this is a test")
	sig := c.PrivateKey.Sign(msg)
	for idx := 0; idx < b.N; idx++ {
		if !c.Domain.Verify(msg, &sig) {
			panic("verification failed")
		}
	}
}
