package semiprivate

import (
	"encoding/hex"
	"testing"
)

const (
	ExpectedSHA256HexDigestLength = 64
)

func TestSHA256d(t *testing.T) {
	testString := "Hello, world!"
	expectedDigest := "6246efc88ae4aa025e48c9c7adc723d5c97171a1fa6233623c7251ab8e57602f"

	digestBytes := sha256d([]byte(testString))
	result := hex.EncodeToString(digestBytes[:])

	if len(result) != ExpectedSHA256HexDigestLength {
		t.Fatalf("SHA256d output len is %d, expected %d\n", len(result), ExpectedSHA256HexDigestLength)
	}

	if result != expectedDigest {
		t.Error("SHA256d results didn't match")
	}
}

//This is a complicated key hierarchy, fully described in lafs.pdf.
// H is SHA256d
// RSA keypair, private half denoted SK
//
func TestMutableFile(t *testing.T) {}
