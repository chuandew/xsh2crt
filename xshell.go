package main

import (
	"bytes"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"
)

// XShellSession holds the parsed fields from an XShell .xsh session file.
type XShellSession struct {
	Host     string
	Port     int
	Protocol string // e.g. "SSH", "TELNET"
	Username string
	// EncryptedPassword is the raw base64 string from the file (may be empty).
	EncryptedPassword string
}

// parseXShellSession reads a .xsh file (UTF-16 LE) and extracts connection info.
func parseXShellSession(filename string) (*XShellSession, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	text, err := decodeFileText(raw)
	if err != nil {
		return nil, fmt.Errorf("decode file encoding: %w", err)
	}

	ini := parseINI(text)

	// XShell 8 section names are uppercase with colon separator.
	// We look up with a case-insensitive helper.
	conn := iniSection(ini, "CONNECTION")
	if conn == nil {
		return nil, fmt.Errorf("missing [CONNECTION] section")
	}

	host := iniGet(conn, "Host")
	if host == "" {
		return nil, fmt.Errorf("missing Host in [CONNECTION]")
	}

	portStr := iniGet(conn, "Port")
	port := 22
	if portStr != "" && portStr != "0" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", portStr)
		}
		port = p
	}

	protocol := strings.ToUpper(iniGet(conn, "Protocol"))
	if protocol == "" {
		protocol = "SSH"
	}

	auth := iniSection(ini, "CONNECTION:AUTHENTICATION")
	var username, encPwd string
	if auth != nil {
		username = iniGet(auth, "UserName")
		encPwd = iniGet(auth, "Password")
	}

	return &XShellSession{
		Host:              host,
		Port:              port,
		Protocol:          protocol,
		Username:          username,
		EncryptedPassword: encPwd,
	}, nil
}

// decryptXShellPassword decrypts an XShell master-password-protected password.
//
// XShell stores passwords as:
//
//	Base64( RC4(key, plaintext) || SHA256(plaintext) )
//
// where key = SHA256(masterPassword).
func decryptXShellPassword(encrypted64, masterPassword string) (string, error) {
	// Base64 decode — try standard padding first, then raw (no padding).
	data, err := base64.StdEncoding.DecodeString(encrypted64)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(encrypted64)
		if err != nil {
			return "", fmt.Errorf("base64 decode: %w", err)
		}
	}

	const checksumLen = sha256.Size // 32 bytes

	if len(data) < checksumLen {
		return "", fmt.Errorf("ciphertext too short (%d bytes)", len(data))
	}

	encryptedPart := data[:len(data)-checksumLen]
	storedChecksum := data[len(data)-checksumLen:]

	key := sha256.Sum256([]byte(masterPassword))

	stream, err := rc4.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("RC4 init: %w", err)
	}
	plaintext := make([]byte, len(encryptedPart))
	stream.XORKeyStream(plaintext, encryptedPart)

	computed := sha256.Sum256(plaintext)
	if !bytes.Equal(storedChecksum, computed[:]) {
		return "", fmt.Errorf("checksum mismatch (wrong master password?)")
	}

	return string(plaintext), nil
}

// ─── INI parsing helpers ────────────────────────────────────────────────────

// parseINI parses a simple INI text into a map of section → (key → value).
// Section names are normalised to uppercase for case-insensitive lookup.
// Key names keep their original casing inside the map; use iniGet for lookup.
func parseINI(text string) map[string]map[string]string {
	result := make(map[string]map[string]string)
	currentSection := ""

	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// Normalise section name to uppercase.
			currentSection = strings.ToUpper(trimmed[1 : len(trimmed)-1])
			if _, ok := result[currentSection]; !ok {
				result[currentSection] = make(map[string]string)
			}
			continue
		}

		idx := strings.IndexByte(trimmed, '=')
		if idx < 0 || currentSection == "" {
			continue
		}

		key := strings.TrimSpace(trimmed[:idx])
		value := trimmed[idx+1:]
		result[currentSection][key] = value
	}

	return result
}

// iniSection returns the map for a given section (case-insensitive).
func iniSection(ini map[string]map[string]string, name string) map[string]string {
	return ini[strings.ToUpper(name)]
}

// iniGet returns the value for a key (case-insensitive key match).
func iniGet(section map[string]string, key string) string {
	upper := strings.ToUpper(key)
	for k, v := range section {
		if strings.ToUpper(k) == upper {
			return v
		}
	}
	return ""
}

// ─── Encoding helpers ────────────────────────────────────────────────────────

// decodeFileText decodes file bytes to a UTF-8 string.
// Supports UTF-16 LE (with BOM 0xFF 0xFE), UTF-16 BE (with BOM 0xFE 0xFF),
// and falls back to UTF-8.
func decodeFileText(b []byte) (string, error) {
	if len(b) >= 2 {
		if b[0] == 0xFF && b[1] == 0xFE {
			// UTF-16 LE
			return utf16LEToString(b[2:])
		}
		if b[0] == 0xFE && b[1] == 0xFF {
			// UTF-16 BE
			return utf16BEToString(b[2:])
		}
		// Strip UTF-8 BOM if present
		if b[0] == 0xEF && b[1] == 0xBB && len(b) >= 3 && b[2] == 0xBF {
			return string(b[3:]), nil
		}
	}
	return string(b), nil
}

func utf16LEToString(b []byte) (string, error) {
	if len(b)%2 != 0 {
		b = b[:len(b)-1] // drop trailing odd byte
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16)), nil
}

func utf16BEToString(b []byte) (string, error) {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.BigEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16)), nil
}
