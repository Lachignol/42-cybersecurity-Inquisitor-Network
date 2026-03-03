package main

import (
	"fmt"
	// "github.com/google/gopacket/pcap"
	"os"
	"os/signal"
)

func main() {
	var ip_src string
	var mac_src string
	var ip_target string
	var mac_target string

	if !setup(&ip_src, &mac_src, &ip_target, &mac_target) {
		return
	}
	fmt.Println("VERIFICATION OF ARGS OK BRODY!")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	fmt.Println("Poisoning")

	// Block until a signal is received.
	s := <-c
	fmt.Println("Got signal:", s)
	fmt.Println("ARP TABLE RESTAURATION:", s)

}
