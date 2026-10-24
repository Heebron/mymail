# Public Internet deployment

This guide describes the work required to make a MyMail installation reachable
from the Internet for receiving mail and suitable for sending mail to other
providers. There is no single setting that makes a mail server trusted. The
deployment needs a stable network identity, correct DNS, encrypted client
access, sender-authentication records, and a good sending reputation.

Replace `example.com`, `mail.example.com`, and `<PUBLIC_IP>` with the values for
the deployment.

## 1. Establish a stable network identity

Use a host or VPS with:

- A static public IPv4 address.
- Provider permission for inbound and outbound TCP port `25`.
- A firewall that permits only the mail ports and administration ports that
  are actually needed.
- Reverse DNS (`PTR`) for `<PUBLIC_IP>` pointing to `mail.example.com`.
- Forward DNS (`A`) for `mail.example.com` pointing to `<PUBLIC_IP>`.

Do not publish an `AAAA` record until IPv6 is fully configured, including
firewall rules and reverse DNS. A broken IPv6 path can cause other mail
servers to defer or reject delivery.

Set MyMail's `hostname` to the same fully qualified hostname used by reverse
DNS. This is the name presented in SMTP and IMAP protocol responses:

```yaml
hostname: mail.example.com
```

## 2. Publish receiving DNS

For mail addressed to `example.com`, publish an MX record whose target has an
`A` or `AAAA` record of its own:

```text
example.com.          MX 10 mail.example.com.
mail.example.com.     A  <PUBLIC_IP>
```

The MX target must not be a CNAME. Confirm the records from an external network
before opening the service to the public:

```sh
dig MX example.com
dig A mail.example.com
dig -x <PUBLIC_IP>
```

Configure users with complete email addresses. They are the login IDs, and an
omitted `mailbox` defaults to that full address:

```yaml
users:
  alice@example.com:
    password_sha256: <LOWERCASE_SHA256_HEX>
    # mailbox: alice@example.com  # optional; this is the default
```

An `aliases` entry routes mail to an existing mailbox but does not create a
separate login account. Unknown recipients at configured local or alias domains
are rejected; authenticated users may relay to external domains.

## 3. Configure TLS and public listeners

Obtain a publicly trusted certificate whose SAN includes `mail.example.com`,
for example from Let's Encrypt. The systemd service runs as the unprivileged
`mymail` user, so the certificate and private key must be readable by that user
or its group. Keep the private key mode restrictive:

```sh
install -d -o root -g mymail -m 0750 /etc/mymail
install -o root -g mymail -m 0640 fullchain.pem /etc/mymail/tls.crt
install -o root -g mymail -m 0640 privkey.pem /etc/mymail/tls.key
```

The standard configuration provides:

- SMTP submission on `:587`, with `STARTTLS`.
- An optional cleartext SMTP listener on `:25`.
- IMAP with `STARTTLS` on `:1143`.
- An optional implicit-TLS IMAP listener, normally `:993`.

For public client access, use settings equivalent to:

```yaml
smtp_listen: 0.0.0.0:587
smtp_cleartext_listen: 0.0.0.0:25
imap_listen: 127.0.0.1:1143
imap_tls_listen: 0.0.0.0:993
tls_cert_file: /etc/mymail/tls.crt
tls_key_file: /etc/mymail/tls.key
smtp_require_starttls: true
imap_require_starttls: true
```

Expose TCP `25`, `587`, and `993` in the cloud and host firewalls. The MX
record must reach public TCP `25`. Do not expose plaintext IMAP `:1143`
publicly. If it must be reachable through a proxy, use a TLS-capable proxy or
a TCP pass-through that preserves the `STARTTLS` connection.

MyMail creates one TLS-capable SMTP listener and, separately, an optional
cleartext SMTP listener. It does not provide two independently configured
SMTP policies in one process. The normal deployment is to keep the cleartext
listener on port `25` for server-to-server inbound SMTP and require
`STARTTLS` on port `587` for authenticated users. The port `25` listener does
not advertise `STARTTLS`; SMTP transport encryption for inbound mail therefore
requires a separate fronting MTA or proxy if it is a requirement.

If port `25` must instead be handled by MyMail's TLS-capable listener, choose
one of these designs:

1. Put a TCP proxy or firewall port-forward in front of the TLS-capable
   listener, forwarding public `25` to the internal listener. This allows the
   same endpoint to serve inbound SMTP and authenticated submission.
2. Configure the TLS-capable `smtp_listen` directly on `:25` and provide
   public `:587` through a TCP proxy.
3. Keep `:25` cleartext for ordinary inbound SMTP and use `:587` for all
   authenticated client submission. This is the simplest supported split, but
   inbound transport encryption is opportunistic only when a separate MTA or
   proxy provides it.

When `smtp_require_starttls` is enabled on the submission listener, every
client must issue `STARTTLS` before authentication or `MAIL`. That is
appropriate for `587`. If the TLS-capable listener is instead used for direct
Internet-to-MX mail on `25`, verify that the mandatory TLS policy is compatible
with the sending providers you need to accept; SMTP peers may not all support
mandatory TLS.

The systemd unit supplied by the project binds as `mymail`, so direct binding
to privileged port `25` may require a firewall redirect, socket activation,
capability configuration, or a fronting proxy. Prefer a narrowly scoped
network configuration rather than running the daemon as root.

## 4. Publish sender-authentication DNS

Publish SPF for every domain used in the `From` address. For direct delivery
from this server:

```text
example.com. TXT "v=spf1 ip4:<PUBLIC_IP> -all"
```

If an outbound relay is used, publish the relay provider's prescribed SPF
`include` instead of, or in addition to, the server IP. Keep one SPF record per
domain; multiple SPF records are invalid.

MyMail does not DKIM-sign outbound messages. For reliable delivery, send
through a relay or a separate outbound signing component and publish the
selector it supplies, for example:

```text
selector1._domainkey.example.com. TXT "v=DKIM1; k=rsa; p=<PUBLIC_KEY>"
```

After SPF and DKIM are working, publish DMARC in monitoring mode:

```text
_dmarc.example.com. TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```

Review aggregate reports, correct SPF/DKIM alignment and forwarding issues,
then consider changing the policy to `quarantine` or `reject`. TLS-RPT and
MTA-STS can be added later for transport-policy reporting and enforcement.

## 5. Choose an outbound delivery strategy

MyMail currently delivers external recipients directly to their domain's MX
hosts on TCP port `25`. The direct path:

- Tries MX hosts in preference order.
- Does not negotiate outbound `STARTTLS`.
- Does not provide a durable outbound queue or retry store.
- Does not DKIM-sign messages.

Direct delivery can be useful for controlled testing, but a new or residential
IP address may be blocked, deferred, or rate-limited even when DNS is correct.
For dependable delivery, use this arrangement:

- Receive mail directly with MyMail through the domain's MX record.
- Submit authenticated user mail to MyMail on `587`.
- Forward outbound mail through a reputable authenticated relay that provides
  DKIM signing, queueing, retries, and reputation management.

If direct delivery is required, confirm that TCP `25` is allowed in both
directions, configure PTR/forward DNS, publish SPF/DKIM/DMARC through
additional infrastructure, and build reputation gradually. Monitor temporary
failures rather than repeatedly retrying them manually.

## 6. Run the service securely

Install the provided unit and state directory, then start the daemon:

```sh
install -Dm644 deploy/mymail.service /etc/systemd/system/mymail.service
useradd --system --home-dir /var/lib/mymail --shell /usr/sbin/nologin mymail
install -d -o mymail -g mymail /var/lib/mymail
systemctl daemon-reload
systemctl enable --now mymail
```

Check the service and logs after every configuration or certificate renewal:

```sh
systemctl status mymail
journalctl -u mymail -e
```

Use `password_sha256` rather than plaintext `password` values in the deployed
configuration, restrict the file to the service account, and use the project's
`mymail-password` command to generate hashes. The configurable `auth_throttle`
limits shared by SMTP and IMAP authentication help limit guessing, but they do
not replace firewall rate limits, monitoring, backups, spam filtering, malware
scanning, or regular operating-system updates. Failed-authentication responses
are bounded by `response_delay_max`; this delay does not keep connections open
for the full lockout period.

## 7. Verify externally

Test from a host outside the server's network. Check DNS and TLS first:

```sh
dig MX example.com
dig A mail.example.com
dig -x <PUBLIC_IP>
openssl s_client -starttls smtp -connect mail.example.com:587 \
  -servername mail.example.com
openssl s_client -connect mail.example.com:993 \
  -servername mail.example.com
```

If public port `25` is forwarded to the TLS-capable SMTP listener, test it as
well:

```sh
openssl s_client -starttls smtp -connect mail.example.com:25 \
  -servername mail.example.com
```

Then verify all of the following:

1. A message from an independent provider reaches a configured local mailbox.
2. A user can authenticate with the full email address on `587` and read mail
   through `993`.
3. An unauthenticated session cannot relay to an external domain.
4. An authenticated submission reaches an external test mailbox, either
   directly or through the configured relay.
5. Received headers show passing SPF, DKIM, and DMARC results.
6. Logs show connection, authentication, routing, and delivery outcomes without
   exposing passwords or message contents.

Passing these checks makes the service correctly identifiable and safer to
operate; it cannot guarantee acceptance by every recipient provider. Delivery
decisions also depend on IP reputation, message content, recipient policy, and
the sender-authentication results observed by each provider.