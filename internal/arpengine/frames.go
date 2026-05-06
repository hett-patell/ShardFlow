package arpengine

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildARPReply constructs an Ethernet+ARP reply frame asserting
// (senderMAC, senderIP) at (recipientMAC, recipientIP). The ethL2Src
// argument is what goes in the Ethernet src MAC field — set this to the
// operator's real MAC so the bridge FDB only ever sees frames with our
// real MAC originating from our port. The ARP body's SourceHwAddress is
// senderMAC (which may differ from ethL2Src for spoofed correctives).
func buildARPReply(ethL2Src, senderMAC net.HardwareAddr, senderIP net.IP, recipientMAC net.HardwareAddr, recipientIP net.IP) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       ethL2Src,
		DstMAC:       recipientMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   senderMAC,
		SourceProtAddress: senderIP.To4(),
		DstHwAddress:      recipientMAC,
		DstProtAddress:    recipientIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildARPRequest constructs an ARP REQUEST frame asking who has recipientIP.
// The sender info (senderMAC, senderIP) is what the receiver caches. We use
// ethL2Src as the L2 source MAC so the bridge FDB only ever sees frames with
// our real MAC originating from our port — keeping the FDB clean even when
// the ARP sender info is spoofed.
func buildARPRequest(ethL2Src, senderMAC net.HardwareAddr, senderIP net.IP, recipientMAC net.HardwareAddr, recipientIP net.IP) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       ethL2Src,
		DstMAC:       recipientMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   senderMAC,
		SourceProtAddress: senderIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    recipientIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildGratuitousARP constructs a gratuitous ARP REQUEST: target IP equals
// sender IP. Linux flags this as `is_garp` and forces NEIGH_UPDATE_F_OVERRIDE
// regardless of the locktime check, so the receiver's neighbour entry is
// updated even when poison sends just touched it. Broadcast at L2 so both
// the immediate target and the gateway pick it up. ethL2Src is our real MAC
// to avoid bridge FDB pollution.
func buildGratuitousARP(ethL2Src, senderMAC net.HardwareAddr, senderIP net.IP) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       ethL2Src,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   senderMAC,
		SourceProtAddress: senderIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    senderIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
