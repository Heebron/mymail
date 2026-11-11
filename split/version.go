package split

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// maxHandshakeVersionLength bounds the build version accepted in a handshake.
const maxHandshakeVersionLength = 256

// UnknownPeerVersion is reported for a peer whose handshake carries no build
// version, which identifies a build that predates the version exchange.
const UnknownPeerVersion = "unknown (older build without version exchange)"

// VersionMismatchError reports that the local and remote sides of the split
// link run different MyMail builds. The remote closes such connections.
type VersionMismatchError struct {
	LocalVersion  string
	RemoteVersion string
}

func (e *VersionMismatchError) Error() string {
	return fmt.Sprintf("split version mismatch: local version %s, remote version %s; both sides must run the same MyMail version",
		e.LocalVersion, e.RemoteVersion)
}

// handshake is a parsed TypeHandshake payload.
type handshake struct {
	magic      uint32
	version    string
	hasVersion bool
}

// displayVersion returns the version for logs and errors.
func (h handshake) displayVersion() string {
	if !h.hasVersion {
		return UnknownPeerVersion
	}
	return displayVersion(h.version)
}

// matches reports whether the peer runs the same build version as this side.
func (h handshake) matches(version string) bool {
	return h.hasVersion && h.version == version
}

func displayVersion(version string) string {
	if version == "" {
		return "(empty)"
	}
	return version
}

func marshalHandshake(version string) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(ProtocolMagic))
	writeString(&buf, version)
	return buf.Bytes()
}

// parseHandshake parses a handshake payload. A bare 4-byte magic payload is
// accepted as a peer that sent no version.
func parseHandshake(data []byte) (handshake, error) {
	if len(data) < 4 {
		return handshake{}, fmt.Errorf("handshake payload too short (%d bytes)", len(data))
	}
	h := handshake{magic: binary.BigEndian.Uint32(data[:4])}
	rest := data[4:]
	if len(rest) == 0 {
		return h, nil
	}
	if len(rest) < 4 {
		return handshake{}, fmt.Errorf("handshake version length truncated (%d bytes)", len(rest))
	}
	length := binary.BigEndian.Uint32(rest[:4])
	if length > maxHandshakeVersionLength {
		return handshake{}, fmt.Errorf("handshake version length %d exceeds %d bytes", length, maxHandshakeVersionLength)
	}
	if uint64(length) != uint64(len(rest)-4) {
		return handshake{}, fmt.Errorf("handshake version length %d does not match %d payload bytes", length, len(rest)-4)
	}
	h.version = string(rest[4:])
	h.hasVersion = true
	return h, nil
}
