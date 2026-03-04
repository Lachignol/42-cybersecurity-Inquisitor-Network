package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func launchSniffing(typeToFilter string) {
	fmt.Println("SNIFFING")
	if handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if typeToFilter != "" {
		filterByType(handle)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
	}
}

func filterByType(handler *pcap.Handle) {
	if err := handler.SetBPFFilter("arp"); err != nil {
		panic(err)
	}

}

func handlePacket(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		handleTcpPacket(tcpLayer)
	}
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		handleArpPacket(arpLayer)
	}
	// printAllLayer(packet)
}

func handleTcpPacket(tcpLayer gopacket.Layer) {
	fmt.Print("TCP: ")
	tcp, _ := tcpLayer.(*layers.TCP)
	fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
}

func handleArpPacket(arpLayer gopacket.Layer) {
	fmt.Print("ARP: ")
	arp, _ := arpLayer.(*layers.ARP)
	dst_Mac_adrr := net.HardwareAddr(arp.DstHwAddress)
	src_Mac_adrr := net.HardwareAddr(arp.SourceHwAddress)
	fmt.Printf("[DESTINATION MAC ADDR : %s] [SOURCE MAC ADDR : %s]\n", dst_Mac_adrr, src_Mac_adrr)
}

func printAllLayer(packet gopacket.Packet) {
	for _, layer := range packet.Layers() {
		fmt.Println("PACKET LAYER:", layer.LayerType())
	}
}
