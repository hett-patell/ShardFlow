package arpengine

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildARPReply constructs an Ethernet+ARP reply frame asserting
// (senderMAC, senderIP) at (recipientMAC, recipientIP). Used both for
// poisoning (senderMAC = operator) and for corrective recovery
// (senderMAC = real owner of senderIP).
func buildARPReply(senderMAC net.HardwareAddr, senderIP net.IP, recipientMAC net.HardwareAddr, recipientIP net.IP) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       senderMAC,
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
