package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// generateSecureCRTSession produces the content of a SecureCRT .ini session
// file from a parsed XShell session.
func generateSecureCRTSession(session *XShellSession, masterPassword string) (string, error) {
	var sb strings.Builder

	protocolName := xshellProtocolToSecureCRT(session.Protocol)

	// SecureCRT session files are flat key=value with type prefixes.
	// S: = string, D: = DWORD (32-bit hex, 8 digits).
	writef := func(format string, args ...any) {
		sb.WriteString(fmt.Sprintf(format, args...))
		sb.WriteString("\r\n")
	}

	writef(`S:"Protocol Name"=%s`, protocolName)
	writef(`S:"Hostname"=%s`, session.Host)

	// Port key varies by protocol.
	portKey := "[SSH2] Port"
	switch protocolName {
	case "SSH1":
		portKey = "[SSH1] Port"
	case "Telnet":
		portKey = "[Telnet] Port"
	}
	writef(`D:"%s"=%08x`, portKey, session.Port)

	if session.Username != "" {
		writef(`S:"Username"=%s`, session.Username)
	}

	// Handle password if one is stored and the session uses password auth.
	if session.EncryptedPassword != "" {
		plainPassword, err := decryptXShellPassword(session.EncryptedPassword, masterPassword)
		if err != nil {
			return "", fmt.Errorf("decrypt password: %w", err)
		}

		encPassword, err := encryptSecureCRTPasswordV2(plainPassword, masterPassword)
		if err != nil {
			return "", fmt.Errorf("encrypt password for SecureCRT: %w", err)
		}

		writef(`S:"Password V2"=%s`, encPassword)
		writef(`D:"Session Password Saved"=00000001`)
		// Set password as the first authentication method
		writef(`S:"SSH2 Authentications V2"=password,publickey,keyboard-interactive,gssapi`)
	}

	writef(`D:"Session Startup"=00000000`)

	return sb.String(), nil
}

// xshellProtocolToSecureCRT maps XShell protocol names to SecureCRT equivalents.
func xshellProtocolToSecureCRT(xshellProtocol string) string {
	switch strings.ToUpper(xshellProtocol) {
	case "SSH", "SSH2":
		return "SSH2"
	case "SSH1":
		return "SSH1"
	case "TELNET":
		return "Telnet"
	case "SERIAL":
		return "Serial"
	default:
		return "SSH2"
	}
}

// encryptSecureCRTPasswordV2 encrypts a plaintext password for SecureCRT's
// "Password V2" field using AES-256-CBC with bcrypt_pbkdf2 key derivation.
//
// Algorithm (SecureCRT "03:" format):
//
//	salt = random 16 bytes
//	kdfBytes = bcrypt_pbkdf2(password, salt, rounds=16, keyLen=48)
//	aesKey = kdfBytes[0:32]
//	iv = kdfBytes[32:48]
//	data = [4-byte LE len][password][SHA256(password)][random padding to 16B]
//	ciphertext = AES-256-CBC(aesKey, iv, data)
//	result = "03:" + hex(salt || ciphertext)
func encryptSecureCRTPasswordV2(password, masterPassword string) (string, error) {
	// Generate random salt (16 bytes)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("random salt: %w", err)
	}

	// Use bcrypt_pbkdf2 to derive key (48 bytes: 32 for AES key + 16 for IV)
	kdfBytes, err := bcryptPbkdfKey([]byte(masterPassword), salt, 16, 32+aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("bcrypt_pbkdf2 failed: %w", err)
	}

	aesKey := kdfBytes[:32]
	iv := kdfBytes[32 : 32+aes.BlockSize]

	plainBytes := []byte(password)
	hash := sha256.Sum256(plainBytes)

	// Build plaintext: [4-byte LE length][password bytes][SHA256 hash]
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(plainBytes)))

	data := make([]byte, 0, 4+len(plainBytes)+sha256.Size+aes.BlockSize)
	data = append(data, lenBuf...)
	data = append(data, plainBytes...)
	data = append(data, hash[:]...)

	// Random padding — length is always 1..16 (never 0).
	padLen := aes.BlockSize - (len(data) % aes.BlockSize)
	padding := make([]byte, padLen)
	if _, err := rand.Read(padding); err != nil {
		return "", fmt.Errorf("random padding: %w", err)
	}
	data = append(data, padding...)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("AES init: %w", err)
	}

	ciphertext := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, data)

	// Prepend salt (SecureCRT "03:" format)
	result := append(salt, ciphertext...)
	return "03:" + hex.EncodeToString(result), nil
}
