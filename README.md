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
- Shared SMTP and IMAP authentication throttling defaults to five attempts per
  connection, applies exponential backoff after failures, and tracks failures
  by source IP and account. Failed-authentication responses are delayed by at
  most one second by default, and a successful login clears the associated IP
  and account backoff state.
- Per-user mailbox resolution and password or SHA-256 password authentication.
- YAML configuration with sensible development defaults.

## Build and run

```sh
make VERSION=v1.0.0 mymail
./mymail -version
install -Dm644 deploy/mymail.service /etc/systemd/system/mymail.service
install -Dm644 config.example.yaml /etc/mymail/config.yaml
install -Dm755 mymail /usr/local/bin/mymail
```

The `-version` flag prints the embedded version and exits without loading the
configuration. `make` derives `VERSION` from the latest Git tag and revision
by default; pass `VERSION=...` to set an explicit release version. Builds also
embed `BUILT_ON` as a UTC RFC3339 timestamp, generated automatically by
`make` or passed as a Docker build argument. Direct `go build` commands use
the `devel` and `unknown` fallbacks unless they provide
`-ldflags "-X main.version=... -X main.builtOn=..."`. The startup log includes
both values.

Edit `/etc/mymail/config.yaml`, create the service account and Maildir state
directory, then start the daemon:

```sh
useradd --system --home-dir /var/lib/mymail --shell /usr/sbin/nologin mymail
install -d -o mymail -g mymail /var/lib/mymail
systemctl enable --now mymail
```

The default listeners are cleartext SMTP `:25`, SMTP submission `:587`
(plaintext until `STARTTLS`), and IMAP `:1143`.
Use a reverse proxy, firewall rules, or privileged socket activation when
exposing standard ports. Set `tls_cert_file` and `tls_key_file` to enable
`STARTTLS` on the SMTP submission and IMAP listeners. The cleartext SMTP
listener is configured with `smtp_cleartext_listen`; IMAP can additionally
expose an implicit TLS listener by setting `imap_tls_listen`.
The checked-in `config.example.yaml` demonstrates STARTTLS with certificate
paths under `/etc/mymail`; install those files before starting the service, or
comment the two TLS file entries when running without TLS.

To send a test message through the default SMTP listener, build and run the
small `mymail-send` client:

```sh
go build -o mymail-send ./cmd/mymail-send
./mymail-send -from kpratt@leopard.thepratts.info -to kpratt@leopard.thepratts.info \
  -username kpratt@leopard.thepratts.info -password changeit
```

Use `-server host:port` for another endpoint. The client also accepts
`-subject` and `-body`, plus
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

`config.example.yaml` contains the complete schema. User keys are full email
addresses (for example `alice@example.test`) and are used as login IDs. If
`mailbox` is omitted, it defaults to the full email address; otherwise it is
the directory name below `maildir_root` and must not contain path separators.
A user's optional `aliases` list routes additional recipient
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
Generate a compatible hash with `mymail-password`; it reads a password from
standard input by default, or accepts it as an argument for convenience:

```sh
go build -o mymail-password ./cmd/mymail-password
printf '%s\n' 'changeit' | ./mymail-password
```

The command prints the lowercase SHA-256 hexadecimal string to place in
`password_sha256`.

Configuration values may contain `${ENV_VARIABLE}` placeholders; variables
defined in the daemon's environment are substituted when the file is loaded.
For example:

```yaml
maildir_root: ${HOME}/mymail
```

Placeholders for variables that are not defined are left unchanged.

`tls_cert_file` and `tls_key_file` enable `STARTTLS` on the SMTP
`smtp_listen` and IMAP `imap_listen` endpoints. `imap_tls_listen` additionally
enables an IMAP implicit TLS endpoint and requires both certificate files. TLS
certificate and key paths may also use
environment variables. Set `smtp_require_starttls: true` to require SMTP
clients on `smtp_listen` to negotiate STARTTLS before authenticating or
submitting a message,
and set `imap_require_starttls: true` to require it before IMAP authentication.
Each setting requires both TLS certificate files. The example configuration
enables both settings.

Authentication throttling is enabled by default and is shared by all SMTP and
IMAP listeners. All limits are configurable in the `auth_throttle` section;
the defaults allow five attempts per connection, 20 failures per source IP,
and 10 failures per account within a 15-minute window. Failed attempts begin
with a one-second backoff that grows exponentially to one minute. For example:

```yaml
auth_throttle:
  max_attempts_per_connection: 5
  max_failures_per_ip: 20
  max_failures_per_account: 10
  backoff_base: 1s
  backoff_max: 1m
  response_delay_max: 1s
  failure_window: 15m
```

The settings are:

- `max_attempts_per_connection` limits the number of authentication checks on
  one SMTP or IMAP connection. The next check after the limit is rejected and
  SMTP closes the connection; IMAP returns a `BYE` response. This counter is
  separate for every connection.
- `max_failures_per_ip` tracks failed authentications from one source IP across
  all SMTP and IMAP connections. When the count reaches this value, failures
  use `backoff_max`; it is not a permanent IP ban.
- `max_failures_per_account` tracks failed authentications for one normalized
  account ID across all source IPs and both protocols. When the count reaches
  this value, failures use `backoff_max`; it is not a permanent account ban.
- `backoff_base` is the delay after the first failed authentication. Subsequent
  failures increase the delay exponentially until `backoff_max` is reached.
- `backoff_max` is the largest delay imposed after a failed authentication and
  also the delay used when either failure threshold has been reached. It is the
  lockout window, not the time a connection is held open; it must be at least
  as long as `backoff_base`.
- `response_delay_max` bounds how long SMTP or IMAP waits before returning a
  failed-authentication response. It prevents the server from holding a TCP
  connection for the full backoff, defaults to one second, and may be shorter
  than `backoff_max`.
- `failure_window` controls how long an IP or account's failure state remains
  active. If no failure occurs during this period, its failure count and
  backoff state expire. A successful authentication immediately clears the
  matching IP and account state.

All duration values use Go duration syntax, such as `500ms`, `1s`, `5m`, or
`1h`. Every numeric limit and duration must be greater than zero. Omitting the
`auth_throttle` section, or omitting an individual setting, uses the defaults
shown above. Any configured value must be valid; the settings are not separate
on/off switches. Because the limiter is shared, a failed SMTP login contributes
to the same IP and account state used by IMAP.

For each authentication attempt, the shared limiter first increments the
connection's attempt counter and checks the source IP and normalized account
ID for an active backoff. Attempts over `max_attempts_per_connection` are
rejected. If either the IP or account is in backoff, authentication is rejected
without checking the password. Otherwise, normal authentication proceeds; a
failure records state for both the IP and account, while a successful login
clears both states. Access to the limiter is synchronized across concurrent
SMTP and IMAP connections.

Backoff starts at `backoff_base` and doubles after each failure for the same
key, up to `backoff_max`. Once either failure threshold is reached, the maximum
backoff is used. Failure state expires after `failure_window` without another
failure and is also cleared immediately by a successful authentication. IP
addresses are normalized by removing their port, and account IDs are trimmed
and converted to lowercase.

After each failed authentication, SMTP and IMAP wait for the newly calculated
backoff duration capped at `response_delay_max`, then return the normal failure
response. The wait is bounded and occurs after the limiter releases its mutex;
attempts rejected because of an active backoff or connection limit are not held
open.

SMTP reports an exhausted connection limit and closes the connection; IMAP
reports a `BYE` response. Each allow, backoff, connection-limit, failure, and
reset decision is emitted as a structured authentication throttle log without
password data.

## SMTP processors

Processors implement `plugins.Processor` and are run in registration order
after the SMTP message has been read and before it is delivered. MyMail calls
`Initialize` for every registered processor before opening the mail listeners;
an initialization error is logged as a warning and that processor is omitted
from processing. A processor can update `Message.Data` and set `Message.Folder`
(or return a folder in its `Result`) to route a locally delivered message to a
Maildir++ folder:

```go
spamFilter := plugins.NewKeywordSpamFilter("buy now", "free money", "viagra")
```

Register processors on the chain before starting the listeners:

```go
processors := plugins.New()
_ = processors.Add(spamFilter)
```

Processors must implement `Initialize(context.Context) error` in addition to
`Name` and `Process`.

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