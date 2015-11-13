// A toy implementation of Zooko and Brian Warner's cryptographic permissions
// hierarchy for a mutable file as described in "Tahoe – The Least-Authority
// Filesystem"

package semiprivate

import (
	"crypto/rand"
	"crypto/sha256"
)

const (
	DigestSize       = sha256.Size // 32-byte digests
	SymmetricKeySize = 16          // 128-bit AES keys
)

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

func randBytes(size int) ([]byte, error) {
	randBytes := make([]byte, size)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}

	return randBytes, nil
}
