# `mymail-password`

`mymail-password` reads a password from standard input and writes a bcrypt
hash suitable for a user's `password_hash` configuration field. It does not
accept passwords as positional arguments, so plaintext is not put in process
arguments. Passwords must be non-empty and no longer than bcrypt's 72-byte
input limit. The default bcrypt cost is `bcrypt.DefaultCost`; `-cost` can set a
different bcrypt cost.

Build the tool from the repository root:

```sh
go build -o mymail-password ./cmd/mymail-password
```

For example, in Bash, read a password without echoing it and pass it through
standard input:

```sh
read -s -r -p 'Password: ' MYMAIL_PASSWORD
printf '\n'
export MYMAIL_USER_PASSWORD_HASH="$(printf '%s\n' "$MYMAIL_PASSWORD" | ./mymail-password)"
unset MYMAIL_PASSWORD
```

Provide `MYMAIL_USER_PASSWORD_HASH` to the daemon's environment and reference
it in the YAML configuration:

```yaml
users:
  alice@example.com:
    password_hash: ${MYMAIL_USER_PASSWORD_HASH}
```

The generated hash is not plaintext, but it is still credential material:
restrict access to the environment, configuration, logs, and any storage where
the hash is retained. The tool writes only the hash to standard output and
diagnostics to standard error.