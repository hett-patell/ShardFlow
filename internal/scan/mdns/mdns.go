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

// Query sends a single mDNS-SD PTR query on the named interface and listens
// for window. Each A record observed in a response is passed to onObs.
//
// Note: binds UDP/5353 explicitly — fails with EADDRINUSE on hosts running
// avahi-daemon. Documented v1 limitation; Phase 7 integration tests run in
// netns where avahi isn't present.
func Query(ctx context.Context, ifaceName string, window time.Duration, onObs func(devicestore.Observation)) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("resolve interface %q: %w", ifaceName, err)
	}
	groupAddr, err := net.ResolveUDPAddr("udp4", mdnsAddr)
	if err != nil {
		return err
	}
	// ListenMulticastUDP joins 224.0.0.251 on the named iface (IP_ADD_MEMBERSHIP)
	// and sets IP_MULTICAST_IF, so responses from devices on that segment
	// are delivered even when no other process holds the group membership.
	conn, err := net.ListenMulticastUDP("udp4", iface, &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353})
	if err != nil {
		return fmt.Errorf("listen multicast: %w", err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo(buildQuery(queryFor), groupAddr); err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Now().Add(window)); err != nil {
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
		parseMDNS(buf[:n], src, onObs)
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

// parseMDNS extracts useful records from the response and calls onObs once
// per record found. Handles A (hostname↔IP), SRV (service→target), and
// PTR (service-discovery pointer) records — each independently observable
// in normal Bonjour traffic. Records that don't carry usable identity
// information are skipped without aborting the parse.
func parseMDNS(pkt []byte, src *net.UDPAddr, onObs func(devicestore.Observation)) {
	var p dnsmessage.Parser
	if _, err := p.Start(pkt); err != nil {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				continue
			}
			// Copy r.A into a fresh slice — r.A lives on the stack-allocated
			// parser; aliasing via r.A[:] would be unsafe across iterations.
			onObs(devicestore.Observation{
				Hostname: trimDot(h.Name.String()),
				IP:       net.IP{r.A[0], r.A[1], r.A[2], r.A[3]},
				Seen:     time.Now(),
			})
		case dnsmessage.TypeSRV:
			// SRV's Target field is the actual hostname; the answer
			// header name is the service name (e.g.
			// "Kitchen._printer._tcp.local."). Use Target for the
			// device's hostname and leave IP for an A record to fill in.
			r, err := p.SRVResource()
			if err != nil {
				continue
			}
			target := trimDot(r.Target.String())
			if target == "" {
				continue
			}
			onObs(devicestore.Observation{
				Hostname: target,
				Seen:     time.Now(),
			})
		case dnsmessage.TypePTR:
			// PTR points service.type.local. → instance-name.service.type.local.
			// The pointed-to name carries the device's friendly instance name,
			// which is genuinely useful when no A record was sent in the same
			// response (common with Apple printers / Sonos). Skip the
			// generic _services._dns-sd._udp PTR (the meta-service answer to
			// our own query), since its target is just a service-type and
			// not a device.
			r, err := p.PTRResource()
			if err != nil {
				continue
			}
			ownerName := trimDot(h.Name.String())
			if strings.HasPrefix(ownerName, "_services._dns-sd._udp") {
				continue
			}
			ptrName := trimDot(r.PTR.String())
			if ptrName == "" {
				continue
			}
			onObs(devicestore.Observation{
				Hostname: ptrName,
				Seen:     time.Now(),
			})
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
		}
	}
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }
