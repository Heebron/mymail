# MyMail security notes

This document describes security behavior verified in the current code. It
replaces the generated security reports that previously claimed fixes which
were not present or proposed patches that did not match the implementation.

## Implemented hardening

- **Split-link client authentication:** a configuration with `split_listen`
  must set `split_ca_cert_file`. The split listener uses that CA to verify the
  connecting local peer's TLS client certificate. Existing remote-side split
  configurations without a CA must be updated before they will validate.
- **Port 25 SMTP authentication:** when `smtp_cleartext_listen` is enabled, it
  offers STARTTLS using the configured certificate, hides AUTH before TLS, and
  rejects plaintext AUTH with `530`. It still accepts unauthenticated inbound
  SMTP `MAIL` transactions without TLS so normal MX delivery can work.
- **Outbound SMTP transport:** when an MX advertises STARTTLS, MyMail attempts
  an encrypted connection and sends EHLO again after upgrading. TLS certificate
  and hostname verification results are logged, but verification failure does
  not stop delivery. If the TLS handshake fails, MyMail reconnects to that MX
  once and retries in plaintext.
- **Password storage:** `password_hash` supports bcrypt. The
  `mymail-password` utility reads the password only from standard input, rejects
  empty inputs and passwords over 72 bytes, and outputs a bcrypt hash. Legacy
  `password` and `password_sha256` fields remain supported for compatibility;
  startup warns when unsalted SHA-256 hashes are configured.
- **Authentication comparisons:** cleartext passwords are compared using
  constant-time comparisons of their SHA-256 digests, and SHA-256 hex hashes
  are decoded before constant-time comparison. Unknown-user authentication
  performs a dummy bcrypt comparison. These measures are not a guarantee of
  identical timing for every configured password format or bcrypt cost.

## Operator actions

- Set a unique bcrypt `password_hash` for each account and keep it outside
  version control. The example configuration uses environment-variable
  placeholders; generate hashes with `mymail-password` as described in
  [`CMD_MYMAIL-PASSWORD.md`](CMD_MYMAIL-PASSWORD.md).
- Configure `tls_cert_file` and `tls_key_file` for SMTP TLS. Use port `587` or
  `465` for authenticated submission; port `25` is for inbound SMTP and will
  not accept AUTH until STARTTLS succeeds.
- For split deployments, configure `split_ca_cert_file` on every split listener
  and use certificates issued by that CA for split clients. Avoid
  `split_insecure_skip_verify` except for controlled diagnostics. Keep the
  remote certificate hostname in `split_connect`; if local DNS masking returns
  the wrong address, set `split_connect_ip` to the intended IP. This overrides
  only the TCP destination and preserves hostname and CA-chain verification.
  `split_ignore_server_name` is a weaker alternative: it skips hostname
  verification while still accepting any certificate from a trusted CA for
  that connection. Pair it with a private `split_ca_cert_file` where possible.
  A remote-only instance does not store configured user credentials; it learns
  mailbox addresses from the local and forwards SMTP authentication requests
  to the local over the verified split link.
  Use `split_tls_cert_file` and `split_tls_key_file` for a dedicated split-link
  pair instead of reusing the public SMTP/IMAP certificate. In bidirectional
  mode that certificate must support both client and server authentication, or
  omit EKU restrictions.
  The local sends its public `tls_cert_file` and private `tls_key_file` to the
  remote after each split connection, so a remote-only instance needs no copy
  of the public SMTP certificate or its private key on disk. The key is sent
  only over the mutually authenticated split link, never when
  `split_insecure_skip_verify` is enabled, and the remote holds it in memory
  only. The remote checks that the received key matches the certificate and
  that the certificate is currently valid, and warns when it does not cover
  `hostname`. Anyone who controls the remote host can read that key, but such
  a host already handles the mail traffic in plaintext. Split-link mail and
  mailbox-list frames are independently DEFLATE-compressed when that reduces
  their size; authentication, certificate, and control frames are excluded.
  Each frame has a fresh compression context, so attacker-controlled message
  data is not compressed in the same context as secrets. Decompression is
  capped at 64 MiB per frame.
- Configure `imap_require_starttls: true` when IMAP authentication must require
  encryption; IMAP's cleartext listener otherwise permits plaintext login.
- Restrict `health_listen` to trusted networks or a local interface if the
  health endpoint should not be public, and use the built-in `auth_throttle`
  settings to tune authentication limits.

## Known limitations not addressed here

- Outbound STARTTLS is opportunistic, not enforced. A certificate validation
  failure is logged but mail is still sent, and a failed handshake triggers a
  plaintext retry. This protects confidentiality only when the remote MX
  supports a successful upgrade; it does not provide authenticated transport
  in every delivery or prevent downgrade attacks.
- Legacy cleartext and SHA-256 password fields are still accepted. SHA-256 is
  unsalted and fast, and cleartext configuration values are exposed if the
  configuration file is disclosed; migrate both to bcrypt hashes.
- IMAP permits plaintext authentication unless `imap_require_starttls` is set.
- Authenticated SMTP users may choose arbitrary `MAIL FROM` addresses; sender
  ownership enforcement is not implemented.
- The example health endpoint binds to `0.0.0.0:8080`; deployments should
  change that if public health checks are not intended.
- Direct MX delivery has no durable outbound queue or retry store.
- A remote-only instance without its own `tls_cert_file` has no SMTP
  certificate after it restarts until the local reconnects. During that time
  port 465 handshakes fail, port 587 cannot accept submissions, and port 25
  accepts inbound mail only in plaintext.

The previously circulated `SECURITY_*` reports overstated timing and
certificate risks, described unapplied changes as implemented, and included
patches that would not compile. They should not be used as patch instructions.