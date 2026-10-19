// Command mymail-password hashes a password for use in password_sha256.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: mymail-password [password]")
		os.Exit(2)
	}

	var password string
	if len(os.Args) == 2 {
		password = os.Args[1]
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read password: %v\n", err)
			os.Exit(1)
		}
		password = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	}

	fmt.Println(passwordHash(password))
}

func passwordHash(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}
