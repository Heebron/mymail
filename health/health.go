// Package health exposes liveness and readiness status for the daemon.
package health

import (
	"net/http"
	"sync/atomic"
)

type Status struct {
	pluginsInitialized atomic.Bool
	shuttingDown       atomic.Bool
	smtpReady          atomic.Int32
	imapReady          atomic.Int32
	expectedSMTP       int32
	expectedIMAP       int32
}

func New(expectedSMTP, expectedIMAP int) *Status {
	return &Status{expectedSMTP: int32(expectedSMTP), expectedIMAP: int32(expectedIMAP)}
}

func (s *Status) PluginsInitialized() {
	s.pluginsInitialized.Store(true)
}

// BeginShutdown marks the daemon as draining. Liveness remains healthy while
// readiness fails so traffic can be removed before the listeners stop.
func (s *Status) BeginShutdown() {
	s.shuttingDown.Store(true)
}

func (s *Status) MarkSMTPReady() {
	s.smtpReady.Add(1)
}

func (s *Status) MarkIMAPReady() {
	s.imapReady.Add(1)
}

func (s *Status) Ready() bool {
	return !s.shuttingDown.Load() &&
		s.pluginsInitialized.Load() &&
		s.smtpReady.Load() >= s.expectedSMTP &&
		s.imapReady.Load() >= s.expectedIMAP
}

func (s *Status) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/healthz":
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	case "/readyz":
		if !s.Ready() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready\n"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ready\n"))
	default:
		http.NotFound(writer, request)
	}
}
