package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/stevec7/sshencode/pkg/sshencode"
)

func main() {
	decrypt := flag.String("d", "", "decrypt this data")
	encrypt := flag.String("e", "", "encrypt this data")
	flag.Parse()

	prefix := fmt.Sprintf("%s/.ssh/id_rsa", os.Getenv("HOME"))
	agent, err := sshencode.Configure(prefix)
	if err != nil {
		fmt.Printf("Error %s\n", err)
		os.Exit(1)
	}

	var data []byte
	if *decrypt != "" {
		data, err = agent.Decrypt([]byte(*decrypt))
		if err != nil {
			fmt.Printf("Error in decryption, %s\n", err)
			os.Exit(1)
		}
	} else if *encrypt != "" {
		data, err = agent.Encrypt([]byte(*encrypt))
		if err != nil {
			fmt.Printf("Error in encryption, %s\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("%s\n", string(data))
}
