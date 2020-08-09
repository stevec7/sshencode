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

	_, err := rand.Read(challenge[:])
	if err != nil {
		return []byte{}, fmt.Errorf("filling challenge buffer, %s", err)
	}

	sig, err := sign(a.signers, challenge[:])
	if err != nil {
		return []byte{}, fmt.Errorf("signing, %s", err)
	}

	cipher, err := sshcryptactions.EncryptWithPassword(sig.Blob, b)
	if err != nil {
		return []byte{}, err
	}
	result := sshcryptdata.EncodeChallengeCipherText(challenge[:], cipher)

	return []byte(result), nil
}
