package sshencode

import (
	"fmt"

	"4d63.com/sshcrypt/lib/sshcryptactions"
	"4d63.com/sshcrypt/lib/sshcryptdata"
)

// Decrypt receives bytes and decrypts them into a string
func (a *Agent) Decrypt(b []byte) ([]byte, error) {
	challenge, cipherText, err := sshcryptdata.DecodeChallengeCipherText(string(b))
	if err != nil {
		return []byte{}, fmt.Errorf("%s", err)
	}
	sig, err := sshcryptactions.Sign(a.signer, challenge)
	if err != nil {
		return []byte{}, fmt.Errorf("%s", err)
	}

	clearText, ok, err := sshcryptactions.DecryptWithPassword(sig.Blob, cipherText)
	if err != nil {
		return []byte{}, fmt.Errorf("%s", err)
	}
	if !ok {
		return []byte{}, fmt.Errorf("couldnt decrypt")
	}
	return []byte(clearText), nil
}
