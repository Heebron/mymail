# Contributing to MyMail

Thank you for your interest in contributing to MyMail. MyMail is a concurrent
SMTP and IMAP server written in Go and maintained as a real-world, self-hosted
mail system.

## Before You Start

- Read the [README](README.md) to understand the project and its deployment
  options.
- Search existing issues before opening a new one.
- For significant changes, open an issue first so the proposed design can be
  discussed before implementation.
- Do not include passwords, private keys, personal mail, or other sensitive
  information in issues, pull requests, tests, or logs.

## Development Setup

Install a supported Go toolchain, clone the repository, and verify the build
from the project root:

```sh
go test ./...
```

The project includes example configuration in `config.example.yaml`. Use a
separate development configuration and Maildir when running the server locally.

## Making Changes

1. Create a focused branch from `master`.
2. Make the smallest change that completely addresses the issue.
3. Add or update tests for behavior changes and bug fixes.
4. Keep public behavior, configuration changes, and operational implications
   documented in the README or relevant documentation.
5. Run formatting and the relevant tests before submitting the change:

   ```sh
   gofmt -w <changed-go-files>
   go test -race ./...
   ```

## Code Standards

- Follow standard Go conventions and the existing style of the package being
  changed.
- Prefer clear, simple implementations over broad refactors.
- Preserve concurrent-safety guarantees and avoid blocking SMTP, IMAP, or
  health request handling unnecessarily.
- Redact authentication credentials and message contents from logs.
- Keep changes focused; submit unrelated cleanup separately.

## Pull Requests

Pull requests should:

- Explain the problem and the behavior that changed.
- Describe configuration, deployment, or compatibility implications.
- Include the tests and validation commands that were run.
- Include documentation updates when user-visible behavior changes.
- Keep commits reviewable and use a concise, imperative commit subject.

Before requesting review, confirm that the working tree is clean, tests pass,
and no sensitive files or data are included in the changes.

## Reporting Security Issues

Do not disclose security vulnerabilities in a public issue. Contact the project
maintainer privately with a description of the vulnerability, affected versions,
and a minimal reproduction when it is safe to provide one.

## Contributors

- **Ken Pratt** — project maintainer and operator.
- **Junie** (`junie@jetbrains.com`) — JetBrains AI coding agent contributing
  implementation, testing, and documentation under maintainer direction.

The project was initially created and is being maintained as an experiment in
using AI-assisted software development for a production-like, self-hosted mail
system. All contributions remain subject to review by the project maintainer.
