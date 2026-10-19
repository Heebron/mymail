# MyMail

MyMail is a combined, concurrent SMTP receiving and IMAP4rev1 server written
in Go. Messages are stored as standard Maildir files, with one mailbox per
configured user. The binary is designed to run as a long-lived `systemd`
service.

## Features

- Atomic Maildir delivery using `tmp` followed by a rename into `new`; IMAP
  reads both `new` and `cur` and preserves message UIDs when files move or are
  reordered.
- Concurrent SMTP sessions with `EHLO`, `MAIL`, `RCPT`, `DATA`, `RSET`, `AUTH
  PLAIN`, and `AUTH LOGIN`.
- Recipient validation prevents delivery to unknown users on configured local domains;
  recipients at other domains are forwarded to that domain's MX host only after SMTP
  authentication.
- Receiving-side processor chain for spam filtering, malware scanning, or
  other application-specific policies.
- IMAP4rev1 access to `INBOX` and user-created folders, including `CAPABILITY`, `NOOP`, `LOGIN`,
  `AUTHENTICATE`, `SELECT`, `EXAMINE`, `LIST`, `LSUB`, `NAMESPACE`, `ID`,
  `IDLE` notifications for newly delivered messages, `STATUS`, `APPEND`, `FETCH`,
  `STORE`, `SEARCH`, `COPY`, `CHECK`,
  `EXPUNGE`, `CLOSE`, `LOGOUT`, and the corresponding `UID FETCH`, `UID STORE`,
  `UID SEARCH`, `UID COPY`, and `UID EXPUNGE` actions. `APPEND` and `COPY`
  report `APPENDUID` and `COPYUID` responses with the `UIDPLUS` capability;
  `STARTTLS` is available when TLS is configured.
- Authenticated users can create, select, rename, and delete Maildir folders
  with `CREATE`, `LIST`, `SELECT`, `RENAME`, and `DELETE`; folders are listed as
  top-level siblings of `INBOX`, while nested folders use dot notation. The
  server also accepts `INBOX.Parent.Child` and `INBOX/Parent/Child` aliases, and
  folder messages can be appended to or copied into the selected user's folders.
- Structured SMTP logs show connection actions, recipient routing, processing
  decisions, and local or forwarded delivery outcomes; authentication payloads
  and message contents are redacted.
- Structured logs include every IMAP action and session state; authentication
  credentials are redacted. Production logs are queued asynchronously so a
  slow log destination does not block SMTP or IMAP request handling. The
  bounded queue drops records under sustained output overload and is drained
  during graceful shutdown.
- Per-user mailbox resolution and password or SHA-256 password authentication.
- YAML configuration with sensible development defaults.

## Build and run

```sh
go build -o mymail ./cmd/mymail
install -Dm644 deploy/mymail.service /etc/systemd/system/mymail.service
install -Dm644 config.example.yaml /etc/mymail/config.yaml
install -Dm755 mymail /usr/local/bin/mymail
```

Edit `/etc/mymail/config.yaml`, create the service account and Maildir state
directory, then start the daemon:

```sh
useradd --system --home-dir /var/lib/mymail --shell /usr/sbin/nologin mymail
install -d -o mymail -g mymail /var/lib/mymail
systemctl enable --now mymail
```

The default development listeners are non-TLS SMTP `:2525` and IMAP `:1143`.
Use a reverse proxy, firewall rules, or privileged socket activation when
exposing standard ports. Optional implicit TLS listeners can run simultaneously
with the non-TLS listeners by setting `smtp_tls_listen` and `imap_tls_listen`,
along with `tls_cert_file` and `tls_key_file`.

To send a test message through the default SMTP listener, build and run the
small `mymail-send` client:

```sh
go build -o mymail-send ./cmd/mymail-send
./mymail-send -from kpratt@leopard.thepratts.info -to kpratt@leopard.thepratts.info \
  -username kpratt -password changeit
```

Use `-server host:port` for another endpoint, `-tls` for an implicit TLS
listener, and `-insecure-skip-verify` only when testing with a certificate that
cannot be verified. The client also accepts `-subject` and `-body`, plus
repeatable or comma-separated `-to`, `-cc`, and `-bcc` options. CC addresses
are included in the message headers; BCC addresses are submitted to SMTP but
are omitted from the message. SMTP authentication is required when relaying to
an external domain, while local deliveries can still be accepted without
authentication.

Recipients whose domain is not configured as local are relayed directly to the
domain's MX host on port 25 only for authenticated SMTP sessions. MyMail tries MX
hosts in preference order and returns a temporary SMTP failure if none accepts the
message. Unauthenticated external recipients are rejected during `RCPT TO`; this
prevents the server from operating as an open relay.

## Configuration

`config.example.yaml` contains the complete schema. User keys are accepted as
full addresses (for example `alice@example.test`) or local names. `mailbox`
is the directory name below `maildir_root`; it must not contain path
separators. A user's optional `aliases` list routes additional recipient
addresses to the same mailbox without creating separate login accounts. For
example:

```yaml
users:
  kpratt@leopard.thepratts.info:
    password: changeit
    mailbox: kpratt
    aliases:
      - kenpratt@comcast.net
      - kpratt@thepratts.info
      - stashcan@comcast.net
```

Alias domains are treated as configured local domains, so unknown recipients
at those domains are rejected rather than forwarded. Prefer `password_sha256`
for a configuration file rather than
plaintext `password` values, and restrict the file to the service account.
Configuration values may contain `${ENV_VARIABLE}` placeholders; variables
defined in the daemon's environment are substituted when the file is loaded.
For example:

```yaml
maildir_root: ${HOME}/mymail
```

Placeholders for variables that are not defined are left unchanged.

`smtp_tls_listen` and `imap_tls_listen` enable implicit TLS endpoints; either
one requires both certificate files. The non-TLS `smtp_listen` and `imap_listen`
endpoints remain active at the same time. TLS certificate and key paths may
also use environment variables.

## SMTP processors

Processors implement `plugins.Processor` and are run in registration order
after the SMTP message has been read and before it is delivered:

```go
spamFilter := plugins.NewKeywordSpamFilter("buy now", "free money", "viagra")
```

Register processors on the chain before starting the listeners:

```go
processors := plugins.New()
_ = processors.Add(spamFilter)
```

See `plugins/example_test.go` for a complete, executable example that builds
the chain and processes a message.

`KeywordSpamFilter` is deliberately a small example, not a production spam
classifier. Replace it with a processor that calls the spam-scoring service or
library used by your deployment. Do not register it if the configured keywords
are not appropriate for your users.

Processor instances must be safe for concurrent calls. Returning an error or
panicking produces a temporary SMTP failure; returning `Reject`,
`TemporaryFailure`, or `Discard` stops the chain. The command currently ships
with an empty chain, making it a safe extension point for application-specific
processors.

## Tests

Run the tests from this directory with:

```sh
GOWORK=off go test -race ./...
```

`GOWORK=off` is needed when the parent directory has a Go workspace that does
not include this standalone module.