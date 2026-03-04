package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <xshell-dir> <securecrt-dir> <master-password>\n", os.Args[0])
		os.Exit(1)
	}

	xshellDir := os.Args[1]
	securecrtDir := os.Args[2]
	masterPassword := os.Args[3]

	if _, err := os.Stat(xshellDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: XShell directory does not exist: %s\n", xshellDir)
		os.Exit(1)
	}

	var converted, skipped int

	err := filepath.Walk(xshellDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: cannot access %s: %v\n", path, err)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".xsh") {
			return nil
		}

		relPath, err := filepath.Rel(xshellDir, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: cannot compute relative path for %s: %v\n", path, err)
			skipped++
			return nil
		}

		// Replace .xsh extension with .ini
		ext := filepath.Ext(relPath)
		outRelPath := relPath[:len(relPath)-len(ext)] + ".ini"
		outPath := filepath.Join(securecrtDir, outRelPath)

		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: cannot create output directory for %s: %v\n", outPath, err)
			skipped++
			return nil
		}

		if err := convertSession(path, outPath, masterPassword); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: skipped  %-60s  (%v)\n", relPath, err)
			skipped++
		} else {
			fmt.Printf("  OK    %s\n", relPath)
			converted++
		}

		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nDone: %d converted, %d skipped\n", converted, skipped)
}

func convertSession(xshellPath, securecrtPath, masterPassword string) error {
	session, err := parseXShellSession(xshellPath)
	if err != nil {
		return err
	}

	content, err := generateSecureCRTSession(session, masterPassword)
	if err != nil {
		return err
	}

	return os.WriteFile(securecrtPath, []byte(content), 0600)
}
