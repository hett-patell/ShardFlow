// Package oui maps MAC OUI prefixes (first 24 bits) to vendor strings,
// using an IEEE OUI database embedded at build time.
package oui

import (
	_ "embed"
	"fmt"
	"net"
	"strings"
	"sync"
)

//go:embed data/oui.txt
var rawDB string

var (
	once  sync.Once
	byOUI map[uint32]string
)

func load() {
	byOUI = make(map[uint32]string, 32000)
	for _, line := range strings.Split(rawDB, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "AABBCC Vendor Name, Inc."
		fields := strings.SplitN(line, " ", 2)
		if len(fields) != 2 {
			continue
		}
		prefix, err := parseOUI(fields[0])
		if err != nil {
			continue
		}
		byOUI[prefix] = strings.TrimSpace(fields[1])
	}
}

func parseOUI(s string) (uint32, error) {
	// IEEE OUI database lines are bare 6-hex-char prefixes ("3C22FB").
	// net.ParseMAC requires explicit separators, so insert them.
	if len(s) < 6 {
		return 0, fmt.Errorf("oui prefix too short: %q", s)
	}
	hw, err := net.ParseMAC(s[0:2] + ":" + s[2:4] + ":" + s[4:6] + ":00:00:00")
	if err != nil {
		return 0, err
	}
	return uint32(hw[0])<<16 | uint32(hw[1])<<8 | uint32(hw[2]), nil
}

// Lookup returns the vendor string for the OUI of m, or "" if unknown.
func Lookup(m net.HardwareAddr) string {
	if len(m) < 3 {
		return ""
	}
	once.Do(load)
	prefix := uint32(m[0])<<16 | uint32(m[1])<<8 | uint32(m[2])
	return byOUI[prefix]
}
