// Package ssdp issues an SSDP M-SEARCH and parses responses for SERVER /
// USN headers, extracting model strings into observations.
package ssdp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
)

const ssdpAddr = "239.255.255.250:1900"

const mSearchTemplate = "M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n" +
	"ST: ssdp:all\r\n\r\n"

// Query sends one M-SEARCH and listens for window. Each response with a
// usable SERVER header produces an observation keyed by the source IP
// (caller resolves IP→MAC via devicestore later).
func Query(ctx context.Context, ifaceName string, window time.Duration, onObs func(devicestore.Observation)) error {
	addr, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo([]byte(mSearchTemplate), addr); err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Now().Add(window)); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil
			}
			return err
		}
		if obs, ok := parseSSDPResponse(buf[:n], src.IP); ok {
			onObs(obs)
		}
	}
}

func parseSSDPResponse(b []byte, ip net.IP) (devicestore.Observation, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(b))), nil)
	if err != nil {
		return devicestore.Observation{}, false
	}
	server := strings.TrimSpace(resp.Header.Get("SERVER"))
	if server == "" {
		return devicestore.Observation{}, false
	}
	return devicestore.Observation{
		IP:     append(net.IP{}, ip...),
		Vendor: server,
		Seen:   time.Now(),
	}, true
}
