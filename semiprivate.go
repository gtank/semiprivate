// A toy implementation of Zooko and Brian Warner's cryptographic permissions
// hierarchy for a mutable file as described in "Tahoe – The Least-Authority
// Filesystem"

package semiprivate

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"io"
)

const (
	DigestSize        = sha256.Size // 32-byte digests
	AsymmetricKeySize = 2048        // 2048-bit RSA keys
	SymmetricKeySize  = 16          // 128-bit AES keys
	TagWKFromSK       = "tag_wk_from_sk_v1"
	TagRKFromWK       = "tag_rk_from_wk_v1"
)

type File interface {
	io.ReadWriter
	Verify(cap []byte) error
}

type MutableFile struct {
	SK *rsa.PrivateKey
	VK crypto.PublicKey
	WK []byte
	RK []byte
}

func sha256d(data []byte) [DigestSize]byte {
	digest := sha256.Sum256(data)
	return sha256.Sum256(digest[:])
}

func taggedHash(tag string, data []byte) [DigestSize]byte {
	var input []byte
	input = append(input, []byte(tag)...)
	input = append(input, data...)
	return sha256d(input)
}

func truncHash(tag string, data []byte, length int) []byte {
	digest := taggedHash(tag, data)
	return digest[:length]
}

func NewMutableFile() (*MutableFile, error) {
	keyPair, err := rsa.GenerateKey(rand.Reader, AsymmetricKeySize)
	if err != nil {
		return nil, err
	}

	encodedSK := x509.MarshalPKCS1PrivateKey(keyPair)
	wk := truncHash(TagWKFromSK, encodedSK, SymmetricKeySize)
	rk := truncHash(TagRKFromWK, wk, SymmetricKeySize)

	newFile := &MutableFile{
		SK: keyPair,
		VK: keyPair.Public(),
		WK: wk,
		RK: rk,
	}

	return newFile, nil
}

// func (mf *MutableFile) Read(p []byte) (n int, err error)  {}
// func (mf *MutableFile) Write(p []byte) (n int, err error) {}
// func (mf *MutableFile) Verify(cap []byte) error           {}
