package main

import (
	"fmt"
	"net"
	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func launchSniffing(typeToFilter string, attaquant_mac net.HardwareAddr) {
	handle := createSniffingHandle("eth0")
	defer handle.Close()
	if typeToFilter != "" {
		filterByType(typeToFilter, handle)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet, attaquant_mac)
	}
}

func createSniffingHandle(nameOfdevice string) *pcap.Handle {
	handle, err := pcap.OpenLive(nameOfdevice, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	return handle
}

func filterByType(typeToFilter string, handler *pcap.Handle) {
	if err := handler.SetBPFFilter(typeToFilter); err != nil {
		panic(err)
	}
}

func handlePacket(packet gopacket.Packet, attaquant_mac net.HardwareAddr) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		handleTcpPacket(tcpLayer)
	}
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		handleArpPacket(arpLayer, attaquant_mac)
	}
	// printAllLayer(packet)
}

func handleTcpPacket(tcpLayer gopacket.Layer) {
	tcp, _ := tcpLayer.(*layers.TCP)
	payload := string(tcp.Payload)
	fmt.Printf("TCP: From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
	fmt.Println("Payload :%s\n", payload)
}

func handleArpPacket(arpLayer gopacket.Layer, attaquant_mac net.HardwareAddr) {
	arp, _ := arpLayer.(*layers.ARP)
	dst_ip_addr := net.IP(arp.DstProtAddress)
	dst_Mac_addr := net.HardwareAddr(arp.DstHwAddress)
	src_ip_addr := net.IP(arp.SourceProtAddress)
	src_Mac_addr := net.HardwareAddr(arp.SourceHwAddress)
	if !reflect.DeepEqual(src_Mac_addr, attaquant_mac) {
		fmt.Println("ARP:[DESTINATION IP: %s MAC: %s] [SOURCE IP: %s MAC: %s]", dst_ip_addr, dst_Mac_addr, src_ip_addr, src_Mac_addr)
	}
}

func printAllLayer(packet gopacket.Packet) {
	for _, layer := range packet.Layers() {
		fmt.Println("PACKET LAYER:", layer.LayerType())
	}
}
