// Command mymail-password generates a bcrypt password hash from standard input.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "mymail-password: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("mymail-password", flag.ContinueOnError)
	flags.SetOutput(stderr)
	cost := flags.Int("cost", bcrypt.DefaultCost, "bcrypt cost (4-31)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("password arguments are not accepted; provide the password on standard input")
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("read password from standard input: %w", err)
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	if len([]byte(password)) > 72 {
		return fmt.Errorf("password must not exceed 72 bytes (bcrypt limit)")
	}
	hash, err := passwordHash(password, *cost)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, hash)
	return err
}

func passwordHash(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("generate bcrypt hash: %w", err)
	}
	return string(hash), nil
}
