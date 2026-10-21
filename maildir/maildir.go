// Package maildir provides a concurrent-safe Maildir mailbox store.
package maildir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrInvalidMailbox = errors.New("invalid mailbox name")

// Message is the metadata needed by the IMAP server for one Maildir message.
type Message struct {
	InternalDate time.Time
	Flags        map[byte]bool
	Filename     string
	Path         string
	Size         int64
	UID          uint32
	Recent       bool
}

// Store manages mailboxes below Root. A Maildir write is committed with one
// rename, so readers never observe a partially written message.
type Store struct {
	Root  string
	locks sync.Map // mailbox name -> *sync.RWMutex
}

func New(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("maildir root is empty")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("create maildir root: %w", err)
	}
	return &Store{Root: root}, nil
}

func (s *Store) mailboxPath(user string) (string, error) {
	parts := strings.Split(strings.TrimSpace(user), "/")
	if len(parts) > 2 || !validMailboxPart(parts[0]) {
		return "", ErrInvalidMailbox
	}
	path := filepath.Join(s.Root, parts[0], "Maildir")
	if len(parts) == 2 {
		if !validMailboxPart(parts[1]) {
			return "", ErrInvalidMailbox
		}
		path = filepath.Join(path, "."+parts[1])
	}
	return path, nil
}

func validMailboxPart(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.ContainsAny(value, `/\`) && !strings.Contains(value, "\x00")
}

func (s *Store) mailboxLock(user string) (*sync.RWMutex, error) {
	if _, err := s.mailboxPath(user); err != nil {
		return nil, err
	}
	lock := &sync.RWMutex{}
	actual, _ := s.locks.LoadOrStore(strings.TrimSpace(user), lock)
	return actual.(*sync.RWMutex), nil
}

// Ensure creates the Maildir directory layout for a user.
func (s *Store) Ensure(user string) error {
	lock, err := s.mailboxLock(user)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()
	return s.ensureLocked(user)
}

func (s *Store) ensureLocked(user string) error {
	path, err := s.mailboxPath(user)
	if err != nil {
		return err
	}
	for _, dir := range []string{path, filepath.Join(path, "tmp"), filepath.Join(path, "new"), filepath.Join(path, "cur")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create mailbox %q: %w", user, err)
		}
	}
	return nil
}

// ListMailboxes returns the child Maildir++ folders belonging to a user.
// INBOX is represented by the user mailbox itself and is not included.
func (s *Store) ListMailboxes(user string) ([]string, error) {
	if !validMailboxPart(strings.TrimSpace(user)) || strings.Contains(user, "/") {
		return nil, ErrInvalidMailbox
	}
	lock, err := s.mailboxLock(user)
	if err != nil {
		return nil, err
	}
	lock.RLock()
	defer lock.RUnlock()
	mailbox, err := s.mailboxPath(user)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(mailbox)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list mailboxes: %w", err)
	}
	var folders []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || len(name) < 2 || name[0] != '.' {
			continue
		}
		if _, err := os.Stat(filepath.Join(mailbox, name, "cur")); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(mailbox, name, "new")); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(mailbox, name, "tmp")); err != nil {
			continue
		}
		folders = append(folders, strings.TrimPrefix(name, "."))
	}
	sort.Strings(folders)
	return folders, nil
}

// RenameMailbox renames a Maildir++ folder and any nested folders belonging
// to the same user. The inbox itself cannot be renamed.
func (s *Store) RenameMailbox(oldUser, newUser string) error {
	oldParts := strings.Split(strings.TrimSpace(oldUser), "/")
	newParts := strings.Split(strings.TrimSpace(newUser), "/")
	if len(oldParts) != 2 || len(newParts) != 2 || oldParts[0] != newParts[0] || !validMailboxPart(oldParts[0]) || !validMailboxPart(oldParts[1]) || !validMailboxPart(newParts[1]) {
		return ErrInvalidMailbox
	}
	if oldParts[1] == "" || newParts[1] == "" || oldParts[1] == newParts[1] {
		return ErrInvalidMailbox
	}
	root := strings.TrimSpace(oldParts[0])
	rootLock, err := s.mailboxLock(root)
	if err != nil {
		return err
	}
	oldLock, err := s.mailboxLock(oldUser)
	if err != nil {
		return err
	}
	newLock, err := s.mailboxLock(newUser)
	if err != nil {
		return err
	}
	rootLock.Lock()
	defer rootLock.Unlock()
	if oldUser < newUser {
		oldLock.Lock()
		defer oldLock.Unlock()
		newLock.Lock()
		defer newLock.Unlock()
	} else {
		newLock.Lock()
		defer newLock.Unlock()
		oldLock.Lock()
		defer oldLock.Unlock()
	}

	mailbox, err := s.mailboxPath(root)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(mailbox)
	if err != nil {
		return fmt.Errorf("list mailboxes: %w", err)
	}
	oldPrefix := "." + oldParts[1]
	newPrefix := "." + newParts[1]
	var folders []string
	for _, entry := range entries {
		if !entry.IsDir() || (entry.Name() != oldPrefix && !strings.HasPrefix(entry.Name(), oldPrefix+".")) {
			continue
		}
		folders = append(folders, entry.Name())
	}
	if len(folders) == 0 {
		return os.ErrNotExist
	}
	for _, folder := range folders {
		suffix := strings.TrimPrefix(folder, oldPrefix)
		if _, err := os.Stat(filepath.Join(mailbox, newPrefix+suffix)); err == nil {
			return os.ErrExist
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for _, folder := range folders {
		suffix := strings.TrimPrefix(folder, oldPrefix)
		if err := os.Rename(filepath.Join(mailbox, folder), filepath.Join(mailbox, newPrefix+suffix)); err != nil {
			return fmt.Errorf("rename mailbox: %w", err)
		}
	}
	return nil
}

// DeleteMailbox removes a Maildir++ folder and any nested folders belonging
// to the same user. The inbox itself cannot be deleted.
func (s *Store) DeleteMailbox(user string) error {
	parts := strings.Split(strings.TrimSpace(user), "/")
	if len(parts) != 2 || !validMailboxPart(parts[0]) || !validMailboxPart(parts[1]) || parts[1] == "" {
		return ErrInvalidMailbox
	}
	root := strings.TrimSpace(parts[0])
	rootLock, err := s.mailboxLock(root)
	if err != nil {
		return err
	}
	mailboxLock, err := s.mailboxLock(user)
	if err != nil {
		return err
	}
	rootLock.Lock()
	defer rootLock.Unlock()
	mailboxLock.Lock()
	defer mailboxLock.Unlock()

	mailbox, err := s.mailboxPath(root)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(mailbox)
	if err != nil {
		return err
	}
	prefix := "." + parts[1]
	var folders []string
	for _, entry := range entries {
		if !entry.IsDir() || (entry.Name() != prefix && !strings.HasPrefix(entry.Name(), prefix+".")) {
			continue
		}
		folders = append(folders, entry.Name())
	}
	if len(folders) == 0 {
		return os.ErrNotExist
	}
	for _, folder := range folders {
		if err := os.RemoveAll(filepath.Join(mailbox, folder)); err != nil {
			return fmt.Errorf("delete mailbox: %w", err)
		}
	}
	return nil
}

// Deliver atomically adds a message to new. data is copied by the operating
// system before this method returns and may be reused by the caller.
func (s *Store) Deliver(user string, data []byte) (Message, error) {
	lock, err := s.mailboxLock(user)
	if err != nil {
		return Message{}, err
	}
	lock.Lock()
	defer lock.Unlock()
	if err := s.ensureLocked(user); err != nil {
		return Message{}, err
	}
	data = normalizeMessage(data)
	mailbox, _ := s.mailboxPath(user)
	unique, err := uniqueName()
	if err != nil {
		return Message{}, err
	}
	tmp := filepath.Join(mailbox, "tmp", unique)
	final := filepath.Join(mailbox, "new", unique)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Message{}, fmt.Errorf("create delivery temporary file: %w", err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return Message{}, fmt.Errorf("write message: %w", err)
	}
	if err := f.Sync(); err != nil {
		return Message{}, fmt.Errorf("sync message: %w", err)
	}
	if err := f.Close(); err != nil {
		return Message{}, fmt.Errorf("close message: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return Message{}, fmt.Errorf("commit message: %w", err)
	}
	ok = true
	return Message{Filename: unique, Path: final, Recent: true, Size: int64(len(data)), InternalDate: time.Now()}, nil
}

func uniqueName() (string, error) {
	var random [12]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", fmt.Errorf("generate message id: %w", err)
	}
	return fmt.Sprintf("%d.%d.%x", time.Now().UnixNano(), os.Getpid(), random[:]), nil
}

func normalizeMessage(data []byte) []byte {
	normalized := make([]byte, 0, len(data)+16)
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '\r':
			normalized = append(normalized, '\r', '\n')
			if index+1 < len(data) && data[index+1] == '\n' {
				index++
			}
		case '\n':
			normalized = append(normalized, '\r', '\n')
		default:
			normalized = append(normalized, data[index])
		}
	}
	return ensureHeaderBodySeparator(normalized)
}

func ensureHeaderBodySeparator(data []byte) []byte {
	if strings.Contains(string(data), "\r\n\r\n") {
		return data
	}
	haveHeader := false
	for start := 0; start < len(data); {
		end := strings.Index(string(data[start:]), "\r\n")
		if end < 0 {
			end = len(data) - start
		}
		lineEnd := start + end
		line := data[start:lineEnd]
		if isHeaderLine(line, haveHeader) {
			haveHeader = true
			if lineEnd == len(data) {
				return append(data, '\r', '\n', '\r', '\n')
			}
			start = lineEnd + 2
			continue
		}
		if haveHeader {
			result := make([]byte, 0, len(data)+2)
			result = append(result, data[:start]...)
			result = append(result, '\r', '\n')
			result = append(result, data[start:]...)
			return result
		}
		break
	}
	return data
}

func isHeaderLine(line []byte, continuation bool) bool {
	if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
		return continuation
	}
	colon := strings.IndexByte(string(line), ':')
	if colon < 1 {
		return false
	}
	for _, character := range line[:colon] {
		if character <= 32 || character >= 127 || character == ':' {
			return false
		}
	}
	return true
}

// List returns a stable snapshot of messages in new and cur, ordered by their
// persistent UID. The returned flag maps are independent from the store. New
// messages receive UIDs in date and filename order before the snapshot is
// sorted, so filesystem date changes cannot reorder existing messages.
func (s *Store) List(user string) ([]Message, error) {
	lock, err := s.mailboxLock(user)
	if err != nil {
		return nil, err
	}
	lock.Lock()
	defer lock.Unlock()
	mailbox, err := s.mailboxPath(user)
	if err != nil {
		return nil, err
	}
	var messages []Message
	for _, dir := range []string{"new", "cur"} {
		entries, err := os.ReadDir(filepath.Join(mailbox, dir))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("list mailbox: %w", err)
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return nil, fmt.Errorf("stat message: %w", err)
			}
			name := entry.Name()
			flags := parseFlags(name)
			messages = append(messages, Message{
				Filename: name,
				Path:     filepath.Join(mailbox, dir, name),
				Recent:   dir == "new",
				Flags:    flags,
				Size:     info.Size(), InternalDate: info.ModTime(),
			})
		}
	}
	sort.SliceStable(messages, func(i, j int) bool {
		if messages[i].InternalDate.Equal(messages[j].InternalDate) {
			return messages[i].Filename < messages[j].Filename
		}
		return messages[i].InternalDate.Before(messages[j].InternalDate)
	})
	if len(messages) == 0 {
		return messages, nil
	}
	uids, nextUID, changed, err := loadUIDs(mailbox)
	if err != nil {
		return nil, err
	}
	for index := range messages {
		key := uidKey(messages[index].Filename)
		uid, ok := uids[key]
		if !ok {
			uid = nextUID
			if nextUID == ^uint32(0) {
				nextUID = 1
			} else {
				nextUID++
			}
			uids[key] = uid
			changed = true
		}
		messages[index].UID = uid
	}
	sort.SliceStable(messages, func(i, j int) bool {
		return messages[i].UID < messages[j].UID
	})
	if changed {
		if err := saveUIDs(mailbox, uids, nextUID); err != nil {
			return nil, err
		}
	}
	return messages, nil
}

const uidListFilename = ".mymail-uidlist"

func uidKey(filename string) string {
	if index := strings.Index(filename, ":2,"); index >= 0 {
		return filename[:index]
	}
	return filename
}

func loadUIDs(mailbox string) (map[string]uint32, uint32, bool, error) {
	data, err := os.ReadFile(filepath.Join(mailbox, uidListFilename))
	if os.IsNotExist(err) {
		return make(map[string]uint32), 1, true, nil
	}
	if err != nil {
		return nil, 0, false, fmt.Errorf("read message UIDs: %w", err)
	}
	uids := make(map[string]uint32)
	nextUID := uint32(1)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(fields) != 2 {
			continue
		}
		if fields[0] == "next" {
			value, parseErr := strconv.ParseUint(fields[1], 10, 32)
			if parseErr == nil && value > 0 {
				nextUID = uint32(value)
			}
			continue
		}
		value, parseErr := strconv.ParseUint(fields[0], 10, 32)
		if parseErr == nil && value > 0 && fields[1] != "" {
			uids[fields[1]] = uint32(value)
		}
	}
	return uids, nextUID, false, nil
}

func saveUIDs(mailbox string, uids map[string]uint32, nextUID uint32) error {
	keys := make([]string, 0, len(uids))
	for key := range uids {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var content strings.Builder
	fmt.Fprintf(&content, "next\t%d\n", nextUID)
	for _, key := range keys {
		fmt.Fprintf(&content, "%d\t%s\n", uids[key], key)
	}
	temporary := filepath.Join(mailbox, uidListFilename+".tmp")
	if err := os.WriteFile(temporary, []byte(content.String()), 0600); err != nil {
		return fmt.Errorf("write message UIDs: %w", err)
	}
	if err := os.Rename(temporary, filepath.Join(mailbox, uidListFilename)); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("commit message UIDs: %w", err)
	}
	return nil
}

func parseFlags(filename string) map[byte]bool {
	flags := make(map[byte]bool)
	if index := strings.Index(filename, ":2,"); index >= 0 {
		for i := index + 3; i < len(filename); i++ {
			flags[filename[i]] = true
		}
	}
	return flags
}

// Read opens a message from a snapshot returned by List.
func (s *Store) Read(message Message) ([]byte, error) {
	data, err := os.ReadFile(message.Path)
	if err != nil {
		return nil, err
	}
	return normalizeMessage(data), nil
}

// SetFlags renames a message according to Maildir's :2, flag suffix.
func (s *Store) SetFlags(user string, message Message, flags map[byte]bool) (Message, error) {
	lock, err := s.mailboxLock(user)
	if err != nil {
		return Message{}, err
	}
	lock.Lock()
	defer lock.Unlock()
	mailbox, err := s.mailboxPath(user)
	if err != nil {
		return Message{}, err
	}
	clean := message.Filename
	if index := strings.Index(clean, ":2,"); index >= 0 {
		clean = clean[:index]
	}
	var flagNames []string
	for _, flag := range []byte{'D', 'F', 'R', 'S', 'T'} {
		if flags[flag] {
			flagNames = append(flagNames, string(flag))
		}
	}
	newName := clean + ":2," + strings.Join(flagNames, "")
	oldPath := message.Path
	if _, err := os.Stat(oldPath); err != nil {
		return Message{}, err
	}
	newPath := filepath.Join(mailbox, "cur", newName)
	if filepath.Dir(oldPath) != filepath.Join(mailbox, "cur") {
		newPath = filepath.Join(mailbox, "cur", newName)
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return Message{}, fmt.Errorf("update message flags: %w", err)
	}
	return Message{Filename: newName, Path: newPath, UID: message.UID, Flags: cloneFlags(flags), Size: message.Size, InternalDate: message.InternalDate}, nil
}

func cloneFlags(flags map[byte]bool) map[byte]bool {
	theCopy := make(map[byte]bool, len(flags))
	for flag, set := range flags {
		if set {
			theCopy[flag] = true
		}
	}
	return theCopy
}

func (s *Store) Delete(message Message) error {
	if err := os.Remove(message.Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DeleteFrom removes a message while coordinating with other operations on
// the same mailbox. Delete is retained for callers that already hold a
// mailbox lock or only need best-effort cleanup of a stale path.
func (s *Store) DeleteFrom(user string, message Message) error {
	lock, err := s.mailboxLock(user)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()
	return s.Delete(message)
}
