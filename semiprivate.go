// A toy implementation of Zooko and Brian Warner's cryptographic permissions
// hierarchy for a mutable file as described in "Tahoe – The Least-Authority
// Filesystem"

package semiprivate

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path"
)

const (
	DigestSize             = sha256.Size // 32-byte digests
	AsymmetricKeySize      = 2048        // 2048-bit RSA keys
	SymmetricKeySize       = 16          // 128-bit AES keys
	SaltSize               = 16          // 128-bit salt
	TagWKFromSK            = "tag_wk_from_sk_v1"
	TagRKFromWK            = "tag_rk_from_wk_v1"
	TagEKFromSaltRK        = "tag_ek_from_salt_rk_v1"
	TagAddressableFilename = "tag_hash_filename_v1"
)

var (
	CapabilityError = errors.New("semiprivate: insufficient capability to perform action")
)

type CapSet struct {
	sk *rsa.PrivateKey
	vk crypto.PublicKey
	wk []byte
	rk []byte
}

type MutableFile struct {
	Cap        *CapSet
	storageDir string
	contents   []byte
	filename   string
	salt       []byte
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

func randBytes(size int) ([]byte, error) {
	randBytes := make([]byte, size)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}

	return randBytes, nil
}

func generateSalt() ([]byte, error) {
	return randBytes(SaltSize)
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
		vk: keyPair.Public(),
		wk: wk,
		rk: rk,
	}
	return newCaps, nil
}

// NewMutableFile takes a set of capabilities with file contents and generates
// metadata necessary to manipulate the file.
func NewMutableFile(c *CapSet, storageDir string, contents []byte) (*MutableFile, error) {
	contentHash := taggedHash(TagAddressableFilename, contents)
	filename := hex.EncodeToString(contentHash[:])
	salt, err := generateSalt()
	if err != nil {
		panic("rand.Read failed!1!!")
	}

	return &MutableFile{
		Cap:        c,
		filename:   filename,
		salt:       salt,
		contents:   contents,
		storageDir: storageDir,
	}, nil
}

// Write writes a file. Format is
// {
//   fileSalt [16]byte
//   gcmNonce [16]byte
//   ciphertext [len(contents)]byte
//   gcmTag [12]byte
//   signature [256]byte
// }
func (m *MutableFile) Write(data []byte) (n int, err error) {

	// TODO check capability derivation chains
	if m.Cap.sk == nil || m.Cap.rk == nil || m.salt == nil {
		return 0, CapabilityError
	}

	ek := truncHash(TagEKFromSaltRK, append(m.Cap.rk, m.salt...), SymmetricKeySize)
	if ek == nil || len(ek) != SymmetricKeySize {
		return 0, aes.KeySizeError(len(ek))
	}

	block, err := aes.NewCipher(ek)
	if err != nil {
		return 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}

	buf := make([]byte, len(m.salt)+len(m.contents)+gcm.NonceSize()+gcm.Overhead())
	copy(buf, m.salt)
	nonce := buf[SaltSize : SaltSize+gcm.NonceSize()]
	if len(nonce) != gcm.NonceSize() {
		return 0, errors.New("you did the slicing wrong")
	}
	_, err = rand.Read(nonce)
	if err != nil {
		panic("rand.Read failed!1!!")
	}
	ciphertext := buf[SaltSize:]
	gcm.Seal(ciphertext, nonce, m.contents, nil)

	hashed := sha256.Sum256(buf)
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.Cap.sk, crypto.SHA256, hashed[:])
	if err != nil {
		return 0, err
	}

	out, err := os.Create(path.Join(m.storageDir, m.filename))
	if err != nil {
		return 0, err
	}
	defer out.Close()
	bufN, err := out.Write(buf)
	if err != nil {
		return 0, err
	}
	sigN, err := out.Write(sig)
	if err != nil {
		return 0, err
	}

	return bufN + sigN, nil
}

// func (mf *MutableFile) Read(p []byte) (n int, err error) {}
// func (mf *MutableFile) Verify(cap []byte) error           {}
