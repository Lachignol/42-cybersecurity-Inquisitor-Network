package main

import (
	"context"
	"fmt"
	"time"
)

func launchPoisoning(ip_src string, mac_src string, ip_target string, mac_target string, ctx context.Context) {
	fmt.Println("POISONING")
	// if handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever); err != nil {
	// 	panic(err)
	// } else {
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Received SIGTERM, exiting loop")
			return
		default:
			fmt.Println("Working...")
			time.Sleep(1 * time.Second)
		}
	}

	// ici cree packet et apres lenvoyer en illimite

	// }
}

func launchRecuperation(ip_src string, mac_src string, ip_target string, mac_target string) {
}

// func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
// 	eth := layers.Ethernet{
// 		SrcMAC:       iface.HardwareAddr,
// 		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
// 		EthernetType: layers.EthernetTypeARP,
// 	}
// 	arp := layers.ARP{
// 		AddrType:          layers.LinkTypeEthernet,
// 		Protocol:          layers.EthernetTypeIPv4,
// 		HwAddressSize:     6,
// 		ProtAddressSize:   4,
// 		Operation:         layers.ARPRequest,
// 		SourceHwAddress:   []byte(iface.HardwareAddr),
// 		SourceProtAddress: []byte(addr.IP),
// 		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
// 	}
// 	buf := gopacket.NewSerializeBuffer()
// 	opts := gopacket.SerializeOptions{
// 		FixLengths:       true,
// 		ComputeChecksums: true,
// 	}
// 	// Send one packet for every address.
// 	for _, ip := range ips(addr) {
// 		arp.DstProtAddress = []byte(ip)
// 		gopacket.SerializeLayers(buf, opts, &eth, &arp)
// 		if err := handle.WritePacketData(buf.Bytes()); err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }
