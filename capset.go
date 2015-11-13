// Copyright 2015 George Tankersley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

// VerifyCap derives a verify capability from an existing CapSet.
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

// ReadCap derives a read-only capability from an existing CapSet.
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

// ReadWriteCap derives a read-write capability from an existing CapSet.
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
