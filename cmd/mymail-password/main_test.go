package main

import "testing"

func TestPasswordHash(t *testing.T) {
	if got, want := passwordHash("changeit"), "00810cf8b94d6fcb9c5de484d3bec4187620b3e2876e59aab90d852fe0f18fb6"; got != want {
		t.Fatalf("passwordHash() = %q, want %q", got, want)
	}
}
