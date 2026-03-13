package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func launchSniffing(global *global, ctx context.Context) {
	handle := createSniffingHandle("eth0")
	defer handle.Close()
	if !global.verbose_mode_activate {
		filterByType("tcp and port 21", handle)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		select {
		case <-ctx.Done():
			return
		default:
			handlePacket(handle, packet, global)
		}
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

func handlePacket(forwardingHandle *pcap.Handle, packet gopacket.Packet, global *global) {
	if etherLayer := packet.Layer(layers.LayerTypeEthernet); etherLayer != nil {
		layerEther, _ := etherLayer.(*layers.Ethernet)
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				layerTcp := tcpLayer.(*layers.TCP)
				printTcpPacket(layerTcp, layerEther, global)
				return
			}
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				layerIcmp := icmpLayer.(*layers.ICMPv4)
				printIcmpPacket(layerIcmp, layerEther, global)
				return
			}
			return
		}
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			layerArp := arpLayer.(*layers.ARP)
			printArpPacket(layerArp, global)
			return
		}
		return
	}
}

func printTcpPacket(tcpLayer *layers.TCP, etherLayer *layers.Ethernet, global *global) {
	if bytes.Equal(etherLayer.DstMAC, global.attaquant_mac) {
		payload := string(tcpLayer.Payload)
		if global.verbose_mode_activate {
			fmt.Printf("PACKET:[TCP]-From src port %d to dst port %d\n", tcpLayer.SrcPort, tcpLayer.DstPort)
			if len(payload) > 0 {
				fmt.Printf("Payload :%s\n", payload)
			}
			return
		} else {
			if strings.Contains(payload, "STOR") {
				fmt.Printf("Names of files exchanged :%s\n", strings.TrimPrefix(payload, "STOR"))
			}
			return
		}
	}
}

func printArpPacket(arpLayer *layers.ARP, global *global) {
	dst_ip_addr := net.IP(arpLayer.DstProtAddress)
	dst_Mac_addr := net.HardwareAddr(arpLayer.DstHwAddress)
	src_ip_addr := net.IP(arpLayer.SourceProtAddress)
	src_Mac_addr := net.HardwareAddr(arpLayer.SourceHwAddress)
	if !bytes.Equal(src_Mac_addr, global.attaquant_mac) {
		fmt.Printf("PACKET:[ARP]-From src ip: %s mac: %s to dst ip: %s mac: %s]\n", src_ip_addr, src_Mac_addr, dst_ip_addr, dst_Mac_addr)
	}
}

func printIcmpPacket(icmpLayer *layers.ICMPv4, etherLayer *layers.Ethernet, global *global) {
	if bytes.Equal(etherLayer.DstMAC, global.attaquant_mac) {
		fmt.Printf("PACKET:[ICMP]-Type %s\n", icmpLayer.TypeCode.String())
	}
}

func printAllLayer(packet gopacket.Packet) {
	fmt.Println("----------LAYERS--OF--PACKET----------")
	for _, layer := range packet.Layers() {
		fmt.Println("PACKET LAYER:", layer.LayerType())
	}
	fmt.Println("--------------------------------------")
}
