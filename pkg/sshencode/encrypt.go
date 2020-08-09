package sshencode

import (
	"crypto/rand"
	"fmt"

	"4d63.com/sshcrypt/lib/sshcryptactions"
	"4d63.com/sshcrypt/lib/sshcryptdata"
)

// Encrypt receives bytes, encrypts them with the private key,
//	and returns bytes, all whilst using the SSH Agent
func (a *Agent) Encrypt(b []byte) ([]byte, error) {
	var challenge [64]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return []byte{}, fmt.Errorf("%s", err)
	}

	sig, err := sshcryptactions.Sign(a.signer, challenge[:])
	if err != nil {
		return []byte{}, fmt.Errorf("%s", err)
	}

	cipherText, err := sshcryptactions.EncryptWithPassword(sig.Blob, b)
	if err != nil {
		return []byte{}, fmt.Errorf("%s", err)
	}

	result := sshcryptdata.EncodeChallengeCipherText(challenge[:], cipherText)

	return []byte(result), nil
}
