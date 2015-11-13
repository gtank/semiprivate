package semiprivate

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"path"
)

const (
	SaltSize               = 16 // 128-bit salt
	TagEKFromSaltRK        = "tag_ek_from_salt_rk_v1"
	TagAddressableFilename = "tag_hash_filename_v1"
)

type MutableFile struct {
	Cap        *CapSet
	storageDir string
	contents   []byte
	filename   string
	salt       []byte
}

func generateSalt() ([]byte, error) {
	return randBytes(SaltSize)
}

// NewMutableFile takes a set of capabilities with file contents and generates
// metadata necessary to manipulate the file.
// TODO requiring contents here is strange. Should be a problem for Write().
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

// ExistingMutableFile takes a set of capabilties and checks that that file
// exists before returning a *MutableFile.
func ExistingMutableFile(c *CapSet, storageDir, filename string) (*MutableFile, error) {
	filePath := path.Join(storageDir, filename)
	if _, err := os.Open(filePath); err != nil {
		return nil, err
	}

	return &MutableFile{
		Cap:        c,
		filename:   filename,
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

	// remember that this is hashing all of salt|nonce|ciphertext|tag
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

// func (m *MutableFile) Read(p []byte) (n int, err error) {}

// Verify checks that the given file and its key derivation salt are unaltered.
func (m *MutableFile) Verify() (bool, error) {
	if m.Cap.vk == nil {
		return false, CapabilityError
	}

	if _, ok := m.Cap.vk.(*rsa.PublicKey); !ok {
		return false, errors.New("semiprivate: VK is not an RSA pubkey")
	}

	filePath := path.Join(m.storageDir, m.filename)
	rawFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return false, err
	}

	// TODO: marshaling scheme should scare me less
	sigSize := AsymmetricKeySize / 8
	sigOffset := len(rawFile) - sigSize
	signature := rawFile[sigOffset : sigOffset+sigSize]

	// for generating EK from RK
	// fileSalt := rawFile[:SaltSize]

	// remember this is hashing all of salt|nonce|ciphertext|tag
	ciphertext := rawFile[:sigOffset]
	hashed := sha256.Sum256(ciphertext)

	err = rsa.VerifyPKCS1v15(m.Cap.vk.(*rsa.PublicKey), crypto.SHA256, hashed[:], signature)
	if err == nil {
		return true, nil
	} else {
		return false, err
	}
}
