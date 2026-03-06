package main

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func launchRecuperation(usurpated_ip net.IP, mac_src net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr) {
	handle := createRecuperationHandle("eth0")
	defer handle.Close()
	for i := 0; i < 100; i++ {
		recuperationARP(handle, usurpated_ip, mac_src, ip_target, mac_target)
		time.Sleep(50 * time.Millisecond)
	}
}

func createRecuperationHandle(nameOfdevice string) *pcap.Handle {
	handle, err := pcap.OpenLive(nameOfdevice, 65535, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	return handle
}

// ca s'apelle une Gratuitous ARP En gro si on set une (request/reply) ARP ou l'ip de destination a la meme que celle de la source
// en broadcast a tout le reseau et en ne notifiant pas l'adresse mac de destination
// ca permet ici de mettre a jour les autres tables du reseau avec les bonnes adresses mac apres avoir poisonner
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
