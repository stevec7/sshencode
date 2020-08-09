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
		return []byte{}, err
	}

	sig, err := sign(a.signers, challenge[:])
	if err != nil {
		return []byte{}, fmt.Errorf("signing, %s", err)
	}

	clearText, ok, err := sshcryptactions.DecryptWithPassword(sig.Blob, cipherText)
	if err != nil {
		return []byte{}, err
	}
	fmt.Printf("arg: %s, clearText: %s, ok: %t\n", string(b), clearText, ok)
	if !ok {
		return []byte(clearText), fmt.Errorf("could not decrypt")
	}
	return []byte(clearText), nil
}
