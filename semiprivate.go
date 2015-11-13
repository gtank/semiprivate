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
	"crypto/rand"
	"crypto/sha256"
)

const (
	DigestSize        = sha256.Size // 32-byte digests
	SymmetricKeySize  = 16          // 128-bit AES keys
	AsymmetricKeySize = 2048        // 2048-bit RSA keys
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
