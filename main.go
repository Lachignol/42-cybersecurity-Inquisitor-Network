package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// var ip_src string
	// var mac_src string
	// var ip_target string
	// var mac_target string

	// if !setup(&ip_src, &mac_src, &ip_target, &mac_target) {
	// 	return
	// }
	// fmt.Println("VERIFICATION OF ARGS OK BRODY!")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	fmt.Println("Poisoning")
	if handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("arp"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Print(packet)
			// packet.ApplicationLayer == layers.ARPReply
			// packet.ApplicationLayer == layers.ARPReply

			// handlePacket(packet)
		}
	}

	// Block until a signal is received.
	s := <-c
	fmt.Println("Got signal:", s)
	fmt.Println("ARP TABLE RESTAURATION:", s)

}
