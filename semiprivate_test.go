package semiprivate

import (
	"bytes"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"path"
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

var fileTests = []struct {
	filename     string
	contents     []byte
	expectedSize int
}{
	{
		filename:     "abcdef0123456789",
		contents:     []byte("Hello, world\n"),
		expectedSize: 313,
	},
}

func TestMutableFileOps(t *testing.T) {
	for _, tt := range fileTests {
		capset, err := NewCapSet()
		if err != nil {
			t.Fatal(err)
		}

		mf, err := NewMutableFile(capset, "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path.Join(mf.storageDir, mf.filename))

		n, err := mf.Write(tt.contents)
		if err != nil {
			t.Fatal(err)
		}
		if n != tt.expectedSize {
			t.Errorf("wrote %d bytes, expected %d", n, tt.expectedSize)
		}

		ok, err := mf.Verify()
		if !ok || err != nil {
			t.Errorf("could not verify written file, %s", err)
		}

		shortRead := make([]byte, len(tt.contents)-1)
		n, err = mf.Read(shortRead)
		if (err != io.ErrShortBuffer) && (bytes.Compare(shortRead, tt.contents[:len(shortRead)]) != 0) {
			t.Error("short read failed")
		}

		fullRead, err := ioutil.ReadAll(mf)
		if bytes.Compare(fullRead, tt.contents) != 0 {
			t.Error("full read failed")
		}

	}
}
