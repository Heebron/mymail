package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadinessRequiresPluginsAndAllListeners(t *testing.T) {
	status := New(2, 1)
	if status.Ready() {
		t.Fatal("status is ready before startup")
	}
	status.PluginsInitialized()
	status.MarkSMTPReady()
	status.MarkIMAPReady()
	if status.Ready() {
		t.Fatal("status is ready before every SMTP listener is ready")
	}
	status.MarkSMTPReady()
	if !status.Ready() {
		t.Fatal("status is not ready after all startup conditions completed")
	}
}

func TestShutdownMakesReadinessFailButHealthPass(t *testing.T) {
	status := New(1, 1)
	status.PluginsInitialized()
	status.MarkSMTPReady()
	status.MarkIMAPReady()
	if !status.Ready() {
		t.Fatal("status is not ready before shutdown")
	}

	status.BeginShutdown()
	if status.Ready() {
		t.Fatal("status is ready during shutdown")
	}

	for _, test := range []struct {
		path string
		code int
	}{
		{path: "/healthz", code: http.StatusOK},
		{path: "/readyz", code: http.StatusServiceUnavailable},
	} {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			status.ServeHTTP(response, request)
			if response.Code != test.code {
				t.Fatalf("status = %d, want %d", response.Code, test.code)
			}
		})
	}
}

func TestHealthHandlers(t *testing.T) {
	status := New(1, 1)
	tests := []struct {
		path string
		code int
	}{
		{path: "/healthz", code: http.StatusOK},
		{path: "/readyz", code: http.StatusServiceUnavailable},
		{path: "/unknown", code: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			status.ServeHTTP(response, request)
			if response.Code != test.code {
				t.Fatalf("status = %d, want %d", response.Code, test.code)
			}
		})
	}
}
