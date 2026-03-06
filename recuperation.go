package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func launchRecuperation(usurpated_ip net.IP, mac_src net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr) {
	handle := createRecuperationHandle("eth0")
	defer handle.Close()
	fmt.Println("Launch recuperation")
	for i := 0; i < 100; i++ {
		recuperationARP(handle, usurpated_ip, mac_src, ip_target, mac_target)
		recuperationARP(handle, ip_target, mac_target, usurpated_ip, mac_src)
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Println("Recuperation done")
}

func createRecuperationHandle(nameOfdevice string) *pcap.Handle {
	handle, err := pcap.OpenLive(nameOfdevice, 65535, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	return handle
}

func recuperationARP(handle *pcap.Handle, ip_src net.IP, mac_src net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr) error {
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	eth := layers.Ethernet{
		SrcMAC:       mac_target,
		DstMAC:       broadcast,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(mac_target),
		SourceProtAddress: []byte(ip_target.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
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
