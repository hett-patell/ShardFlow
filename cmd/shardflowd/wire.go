package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/hett-patell/ShardFlow/internal/iface"
)

func preflight(sockPath, realIface string, force, clean bool) error {
	if _, err := os.Stat(sockPath); err == nil {
		if !force {
			return fmt.Errorf("socket %s already exists; another shardflowd running, or pass --force", sockPath)
		}
		_ = os.Remove(sockPath)
	}
	if err := os.MkdirAll(filepathDir(sockPath), 0o755); err != nil {
		return err
	}
	type probe struct {
		name     string
		exists   func() bool
		teardown func()
	}
	exists := func(args ...string) bool {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		return err == nil && len(out) > 0
	}
	run := func(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }

	probes := []probe{
		{"inet shardflow nft table",
			func() bool { return exists("nft", "list", "table", "inet", "shardflow") },
			func() { run("nft", "delete", "table", "inet", "shardflow") }},
		{"netdev shardflow_ingress nft table",
			func() bool { return exists("nft", "list", "table", "netdev", "shardflow_ingress") },
			func() { run("nft", "delete", "table", "netdev", "shardflow_ingress") }},
		{"shardflow0 IFB iface",
			func() bool { return exists("ip", "link", "show", "shardflow0") },
			func() { run("ip", "link", "del", "shardflow0") }},
		{"shardflow-cap dummy iface",
			func() bool { return exists("ip", "link", "show", "shardflow-cap") },
			func() { run("ip", "link", "del", "shardflow-cap") }},
		{realIface + " ingress qdisc",
			func() bool {
				out, err := exec.Command("tc", "qdisc", "show", "dev", realIface, "ingress").CombinedOutput()
				return err == nil && strings.Contains(string(out), "ingress")
			},
			func() { run("tc", "qdisc", "del", "dev", realIface, "ingress") }},
	}
	var orphans []string
	for _, p := range probes {
		if p.exists() {
			orphans = append(orphans, p.name)
		}
	}
	if len(orphans) == 0 {
		return nil
	}
	if !clean {
		return fmt.Errorf("orphaned ShardFlow state from a prior run: %s. Pass --clean-on-start to remove",
			strings.Join(orphans, "; "))
	}
	for _, p := range probes {
		if p.exists() {
			p.teardown()
		}
	}
	return nil
}

func filepathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

func setIPv4Forward(v string) (string, error) {
	prev, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(v+"\n"), 0o644); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(prev)), nil
}

// resolveGatewayMAC sends a directed ARP request for info.Gateway and
// waits up to 2s for a reply, returning the gateway's MAC.
func resolveGatewayMAC(info iface.Info) (net.HardwareAddr, error) {
	handle, err := pcap.OpenLive(info.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, err
	}

	eth := layers.Ethernet{
		SrcMAC:       info.HwAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   info.HwAddr,
		SourceProtAddress: info.IP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    info.Gateway.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &arp); err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(2 * time.Second)
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for time.Now().Before(deadline) {
		select {
		case pkt, ok := <-src.Packets():
			if !ok {
				return nil, errors.New("packet source closed")
			}
			al := pkt.Layer(layers.LayerTypeARP)
			if al == nil {
				continue
			}
			a := al.(*layers.ARP)
			if a.Operation != layers.ARPReply {
				continue
			}
			if !net.IP(a.SourceProtAddress).Equal(info.Gateway.To4()) {
				continue
			}
			return net.HardwareAddr(append([]byte{}, a.SourceHwAddress...)), nil
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, errors.New("timeout waiting for gateway ARP reply")
}
