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
	"bytes"
	"crypto/rsa"
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

		m, err := NewMutableFile(capset, "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path.Join(m.storageDir, m.filename))

		n, err := m.Write(tt.contents)
		if err != nil {
			t.Fatal(err)
		}
		if n != tt.expectedSize {
			t.Errorf("wrote %d bytes, expected %d", n, tt.expectedSize)
		}

		ok, err := m.Verify()
		if !ok || err != nil {
			t.Errorf("could not verify written file, %s", err)
		}

		shortRead := make([]byte, len(tt.contents)-1)
		n, err = m.Read(shortRead)
		if (err != io.ErrShortBuffer) && (bytes.Compare(shortRead, tt.contents[:len(shortRead)]) != 0) {
			t.Error("short read failed")
		}

		fullRead, err := ioutil.ReadAll(m)
		if bytes.Compare(fullRead, tt.contents) != 0 {
			t.Error("full read failed")
		}

	}
}

// TestInvalidSignatureVerify writes garbage to the signature block and tries
// to verify.
func TestInvalidSignatureVerify(t *testing.T) {
	for _, tt := range fileTests {
		capset, err := NewCapSet()
		if err != nil {
			t.Fatal(err)
		}

		m, err := NewMutableFile(capset, "/tmp")
		if err != nil {
			t.Fatal(err)
		}

		_, err = m.Write(tt.contents)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path.Join(m.storageDir, m.filename))

		ok, err := m.Verify()
		if !ok || err != nil {
			t.Errorf("could not verify correct signature, %s", err)
		}

		handle, err := os.OpenFile(path.Join(m.storageDir, m.filename),
			os.O_RDWR, 0)
		if err != nil {
			t.Fatalf("could not open file: %s", err)
		}
		fileInfo, _ := handle.Stat()
		garbage := []byte{0xBA, 0xAD, 0xC0, 0xDE}
		_, err = handle.WriteAt(garbage, fileInfo.Size()-4)
		if err != nil {
			t.Fatal(err)
		}
		handle.Close()

		ok, err = m.Verify()
		if ok || err == nil {
			t.Fatal("verified bad signature!")
		}
	}
}

// TestInvalidSignatureRead writes garbage to the signature block and tries
// to read the file.
func TestInvalidSignatureRead(t *testing.T) {
	for _, tt := range fileTests {
		capset, err := NewCapSet()
		if err != nil {
			t.Fatal(err)
		}

		m, err := NewMutableFile(capset, "/tmp")
		if err != nil {
			t.Fatal(err)
		}

		_, err = m.Write(tt.contents)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path.Join(m.storageDir, m.filename))

		handle, err := os.OpenFile(path.Join(m.storageDir, m.filename),
			os.O_RDWR, 0)
		if err != nil {
			t.Fatalf("could not open file: %s", err)
		}
		fileInfo, _ := handle.Stat()
		garbage := []byte{0xBA, 0xAD, 0xC0, 0xDE}
		_, err = handle.WriteAt(garbage, fileInfo.Size()-4)
		if err != nil {
			t.Fatal(err)
		}
		handle.Close()

		_, err = ioutil.ReadAll(m)
		if err != rsa.ErrVerification {
			t.Fatal("read the corrupt file anyway")
		}
	}
}
func TestDropWriteCap(t *testing.T) {
	for _, tt := range fileTests {
		capset, err := NewCapSet()
		if err != nil {
			t.Fatal(err)
		}
		capset, err = capset.ReadCap()
		if err != nil {
			t.Fatal(err)
		}

		m, err := NewMutableFile(capset, "/tmp")
		_, err = m.Write(tt.contents)
		if err != CapabilityError {
			t.Fatal("did not detect dropped writecap")
		}
	}
}
