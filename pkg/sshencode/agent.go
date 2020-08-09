package sshencode

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Agent ...
type Agent struct {
	agent agent.ExtendedAgent

	// the pub/private keys in bytes. the private key will normally be
	//	encrypted with a password, but we'll grab that from the ssh agent
	privKey []byte
	pubKey  []byte

	// the signer we get from the ssh agent
	signers ssh.Signer
}

// Configure builds out an agent struct that can be used to
//	easily encrypt/decrypt via methods afterwards
func Configure(sshKeyPrefix string) (*Agent, error) {
	a, err := newAgent()
	if err != nil {
		return a, err
	}

	pub, err := readKey(fmt.Sprintf("%s.pub", sshKeyPrefix))
	if err != nil {
		return a, err
	}

	priv, err := readKey(sshKeyPrefix)
	if err != nil {
		return a, err
	}

	a.privKey = priv
	a.pubKey = pub

	return a, nil
}

// connects to the SSH_AUTH_SOCKET, gets keys added to the keyring, etc
func newAgent() (*Agent, error) {
	newAgent := &Agent{}
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return newAgent, fmt.Errorf("failed to open SSH_AUTH_SOCK: %v", err)
	}

	a := agent.NewClient(conn)
	signers, err := a.Signers()
	if err != nil {
		return newAgent, fmt.Errorf("getting signers, %s", err)
	}

	if len(signers) != 1 {
		return newAgent, fmt.Errorf("only 1 signer is supported right now")
	}
	newAgent.agent = a
	newAgent.signers = signers[0]

	return newAgent, nil
}

func readKey(filename string) ([]byte, error) {
	key, err := ioutil.ReadFile(filename)
	if err != nil {
		return []byte{}, fmt.Errorf("reading keyfile '%s', %s", filename, err)
	}
	return key, nil
}
