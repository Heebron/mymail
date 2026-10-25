// Package mymail is the MyMail mail server module.
//
// MyMail combines SMTP message reception, IMAP mailbox access, and HTTP
// health endpoints. Messages are stored in standard Maildir directories.
// The config package loads daemon settings, the plugins package provides the
// receiving-side processing extension point, and the smtp and imap packages
// implement the protocol services. The cmd subdirectories contain the daemon
// and supporting command-line utilities.
package mymail
