package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
)

func main() {
	// typeToFilter := flag.String("f", "", "Type to filter ex: Arp")
	flag.Parse()

	ip_src := "10.0.0.20"
	mac_src := "de:59:be:22:8f:e0"
	ip_target := "10.0.0.30"
	mac_target := "a2:b2:e5:75:d4:7a"

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
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		cancel()
	}()

	launchPoisoning(ip_src, mac_src, ip_target, mac_target, ctx)

	// a decommenter apres pour lancer le sniffing
	// -------------------------------------------------------
	// launchSniffing(*typeToFilter)
	// -------------------------------------------------------

	// Block until a signal is received.
	// s := <-c
	// fmt.Println("Got signal:", s)
	// fmt.Println("ARP TABLE RESTAURATION:", s)

}
