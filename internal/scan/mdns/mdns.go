// Package mdns issues mDNS-SD queries and parses A-record responses into
// (hostname, IP) observations.
package mdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
)

const (
	mdnsAddr = "224.0.0.251:5353"
	queryFor = "_services._dns-sd._udp.local."
)

// Query sends a single mDNS-SD PTR query and listens for window. Each A
// record observed in a response is passed to onObs.
//
// Note: binds UDP/5353 explicitly — fails with EADDRINUSE on hosts running
// avahi-daemon. Documented v1 limitation; Phase 7 integration tests run in
// netns where avahi isn't present.
func Query(ctx context.Context, ifaceName string, window time.Duration, onObs func(devicestore.Observation)) error {
	addr, err := net.ResolveUDPAddr("udp4", mdnsAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 5353})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo(buildQuery(queryFor), addr); err != nil {
		return err
	}
	deadline := time.Now().Add(window)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	buf := make([]byte, 65536)
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
		if obs, ok := parseMDNS(buf[:n], src); ok {
			onObs(obs)
		}
	}
}

func buildQuery(name string) []byte {
	var msg dnsmessage.Message
	msg.Header.Response = false
	msg.Questions = []dnsmessage.Question{{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}}
	b, _ := msg.Pack()
	return b
}

func parseMDNS(pkt []byte, src *net.UDPAddr) (devicestore.Observation, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(pkt); err != nil {
		return devicestore.Observation{}, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return devicestore.Observation{}, false
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				continue
			}
			return devicestore.Observation{
				Hostname: trimDot(h.Name.String()),
				IP:       net.IP(r.A[:]),
				Seen:     time.Now(),
			}, true
		default:
			if err := p.SkipAnswer(); err != nil {
				return devicestore.Observation{}, false
			}
		}
	}
	_ = src
	return devicestore.Observation{}, false
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }
