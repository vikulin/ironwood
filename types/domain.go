package types

import (
	"crypto/ed25519"
	"strings"
)

//Domain type for the Mesh

const (
	PublicKeySize  = ed25519.PublicKeySize
	PrivateKeySize = ed25519.PrivateKeySize
	SignatureSize  = ed25519.SignatureSize
)

type Name [PublicKeySize]byte
type PublicKey [PublicKeySize]byte
type PrivateKey [PrivateKeySize]byte
type Signature [SignatureSize]byte

type Domain struct {
	Name Name
	Key  PublicKey
}

type Crypto struct {
	PrivateKey PrivateKey
	PublicKey  PublicKey
	Domain     Domain
}

func (a Domain) GetNormalizedName() []byte {
	return TruncateZeroBytes(a.Name[:])
}

func TruncateZeroBytes(data []byte) []byte {
	length := len(data)
	for length > 0 && data[length-1] == 0 {
		length--
	}
	return data[:length]
}

func InitDomain() Domain {
	var k [PublicKeySize]byte
	var n [PublicKeySize]byte
	return Domain{
		Key:  k,
		Name: n,
	}
}

func NewDomain(name string, key ed25519.PublicKey) Domain {
	s := strings.ToLower(name)
	var k [PublicKeySize]byte
	var n [PublicKeySize]byte
	copy(k[:], key)
	copy(n[:], []byte(s))
	return Domain{
		Key:  k,
		Name: n,
	}
}

func (key *PrivateKey) Sign(message []byte) Signature {
	var sig Signature
	tmp := ed25519.Sign(ed25519.PrivateKey(key[:]), message)
	copy(sig[:], tmp)
	return sig
}

func (publicKey PublicKey) Equal(comparedKey PublicKey) bool {
	return publicKey == comparedKey
}

func (publicKey PublicKey) Verify(message []byte, sig *Signature) bool {
	return ed25519.Verify(publicKey[:], message, sig[:])
}

func (publicKey PublicKey) ToSlice() []byte {
	return publicKey[:]
}

func (publicKey PublicKey) ToEd() ed25519.PublicKey {
	return publicKey[:]
}

func (domain Domain) Verify(message []byte, sig *Signature) bool {
	return ed25519.Verify(domain.Key[:], message, sig[:])
}

func (a Domain) Equal(comparedDomain Domain) bool {
	return a.Name == comparedDomain.Name
}

func (key PublicKey) Less(comparedKey PublicKey) bool {
	for idx := range key {
		switch {
		case key[idx] < comparedKey[idx]:
			return true
		case key[idx] > comparedKey[idx]:
			return false
		}
	}
	return false
}

func (domain Domain) Addr() Addr {
	return Addr(domain)
}

func (c *Crypto) Init(secret ed25519.PrivateKey, domain Domain) {
	copy(c.PrivateKey[:], secret)
	copy(c.PublicKey[:], secret.Public().(ed25519.PublicKey))
	c.Domain = domain
}

/*********************
 * utility functions *
 *********************/
//func (domain1 domain) treeLess(domain2 domain) bool {
//	return domain1.publicKey().treeLess(domain2.publicKey())
//}

func (domain1 Domain) TreeLess(domain2 Domain) bool {
	for idx := range domain1.Name {
		switch {
		case domain1.Name[idx] < domain2.Name[idx]:
			return true
		case domain1.Name[idx] > domain2.Name[idx]:
			return false
		}
	}
	return false
}

func (key1 Name) TreeLess(key2 Name) bool {
	for idx := range key1 {
		switch {
		case key1[idx] < key2[idx]:
			return true
		case key1[idx] > key2[idx]:
			return false
		}
	}
	return false
}
