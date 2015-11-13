package semiprivate

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
)

const (
	TagWKFromSK = "tag_wk_from_sk_v1"
	TagRKFromWK = "tag_rk_from_wk_v1"
)

var (
	CapabilityError = errors.New("semiprivate: insufficient capability to perform action")
)

type CapSet struct {
	sk *rsa.PrivateKey
	wk []byte
	rk []byte
	vk crypto.PublicKey
}

// NewCapSet generates a new capability set.
func NewCapSet() (*CapSet, error) {
	keyPair, err := rsa.GenerateKey(rand.Reader, AsymmetricKeySize)
	if err != nil {
		return nil, err
	}

	encodedSK := x509.MarshalPKCS1PrivateKey(keyPair)
	wk := truncHash(TagWKFromSK, encodedSK, SymmetricKeySize)
	rk := truncHash(TagRKFromWK, wk, SymmetricKeySize)

	newCaps := &CapSet{
		sk: keyPair,
		wk: wk,
		rk: rk,
		vk: keyPair.Public(),
	}
	return newCaps, nil
}

func (c *CapSet) VerifyCap() (*CapSet, error) {
	if c.vk == nil {
		return nil, CapabilityError
	}

	return &CapSet{
		sk: nil,
		wk: nil,
		rk: nil,
		vk: c.vk,
	}, nil
}

func (c *CapSet) ReadCap() (*CapSet, error) {
	if c.vk == nil || c.rk == nil {
		return nil, CapabilityError
	}

	return &CapSet{
		sk: nil,
		wk: nil,
		rk: c.rk,
		vk: c.vk,
	}, nil
}

func (c *CapSet) ReadWriteCap() (*CapSet, error) {
	// TODO: store keys on disk and use the original hash caps
	if c.wk == nil || c.rk == nil || c.sk == nil || c.vk == nil {
		return nil, CapabilityError
	}

	return &CapSet{
		sk: c.sk,
		wk: c.wk,
		rk: c.rk,
		vk: c.vk,
	}, nil
}
