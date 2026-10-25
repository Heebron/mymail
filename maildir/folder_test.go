package maildir

import (
	"errors"
	"testing"
)

func TestDeliverToFolder(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeliverToFolder("alice", "Archive", []byte("Subject: archived\n\nbody")); err != nil {
		t.Fatal(err)
	}
	folders, err := store.ListMailboxes("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(folders) != 1 || folders[0] != "Archive" {
		t.Fatalf("folders = %#v", folders)
	}
	messages, err := store.List("alice/Archive")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("folder messages = %d, want 1", len(messages))
	}
}

func TestDeliverToFolderRejectsPathSeparators(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeliverToFolder("alice", "../Archive", []byte("message")); !errors.Is(err, ErrInvalidMailbox) {
		t.Fatalf("error = %v, want ErrInvalidMailbox", err)
	}
}