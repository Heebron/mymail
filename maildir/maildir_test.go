package maildir

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestDeliverListReadAndFlags(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	want := []byte("From: sender@example.test\r\n\r\nhello\r\n")
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := store.Deliver("alice", want); err != nil {
				t.Errorf("deliver: %v", err)
			}
		}()
	}
	group.Wait()
	messages, err := store.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != workers {
		t.Fatalf("got %d messages, want %d", len(messages), workers)
	}
	data, err := store.Read(messages[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("message content changed: got %q", data)
	}
	updated, err := store.SetFlags("alice", messages[0], map[byte]bool{'S': true, 'F': true})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Flags['S'] || !updated.Flags['F'] {
		t.Fatalf("flags not persisted: %#v", updated.Flags)
	}
	if _, err := store.Read(updated); err != nil {
		t.Fatalf("read renamed message: %v", err)
	}
}

func TestRejectsMailboxTraversal(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("../outside"); err != ErrInvalidMailbox {
		t.Fatalf("got %v, want ErrInvalidMailbox", err)
	}
}

func TestFoldersAreListedAndIsolated(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("alice"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("alice/Projects"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("alice/Archive.2026"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("bob/Projects"); err != nil {
		t.Fatal(err)
	}
	folders, err := store.ListMailboxes("alice")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(folders, ","), "Archive.2026,Projects"; got != want {
		t.Fatalf("folders = %q, want %q", got, want)
	}
	if folders, err := store.ListMailboxes("bob"); err != nil || len(folders) != 1 || folders[0] != "Projects" {
		t.Fatalf("bob folders = %#v, error = %v", folders, err)
	}
	if _, err := store.Deliver("alice/Projects", []byte("Subject: folder\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	messages, err := store.List("alice/Projects")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("folder messages = %d, want 1", len(messages))
	}
	if messages, err := store.List("alice"); err != nil || len(messages) != 0 {
		t.Fatalf("INBOX messages = %#v, error = %v", messages, err)
	}
}

func TestRenameMailboxAndNestedFolders(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("alice/Projects"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("alice/Projects.2026"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("alice/Projects", []byte("Subject: project\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("alice/Projects.2026", []byte("Subject: nested\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := store.RenameMailbox("alice/Projects", "alice/Archive"); err != nil {
		t.Fatal(err)
	}
	if messages, err := store.List("alice/Archive"); err != nil || len(messages) != 1 {
		t.Fatalf("renamed messages = %#v, error = %v", messages, err)
	}
	if messages, err := store.List("alice/Archive.2026"); err != nil || len(messages) != 1 {
		t.Fatalf("renamed nested messages = %#v, error = %v", messages, err)
	}
	folders, err := store.ListMailboxes("alice")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(folders, ",") != "Archive,Archive.2026" {
		t.Fatalf("renamed folders = %q", strings.Join(folders, ","))
	}
}

func TestDeleteMailboxAndNestedFolders(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("alice/Projects"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure("alice/Projects.2026"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("alice/Projects", []byte("Subject: project\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Deliver("alice/Projects.2026", []byte("Subject: nested\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteMailbox("alice/Projects"); err != nil {
		t.Fatal(err)
	}
	if folders, err := store.ListMailboxes("alice"); err != nil || len(folders) != 0 {
		t.Fatalf("remaining folders = %#v, error = %v", folders, err)
	}
	if err := store.DeleteMailbox("alice"); err != ErrInvalidMailbox {
		t.Fatalf("delete inbox error = %v, want ErrInvalidMailbox", err)
	}
	if err := store.DeleteMailbox("alice/Projects"); !os.IsNotExist(err) {
		t.Fatalf("delete missing mailbox error = %v, want not-exist", err)
	}
}
