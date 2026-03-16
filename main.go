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
	victime_ip            net.IP
	serveur_ip            net.IP
	serveur_mac           net.HardwareAddr
	attaquant_mac         net.HardwareAddr
	victime_mac           net.HardwareAddr
	verbose_mode_activate bool
}

// ./inquisitor  "10.0.0.20" "02:42:0a:00:00:0B" "10.0.0.10" "02:42:0a:00:00:0A" "02:42:0a:00:00:0C"
// ./inquisitor -v "10.0.0.20" "02:42:0a:00:00:0B" "10.0.0.10" "02:42:0a:00:00:0A" "02:42:0a:00:00:0C"

func initGlob(ip_src net.IP, mac_src net.HardwareAddr, ip_target net.IP, mac_target net.HardwareAddr, attaquant_mac net.HardwareAddr, verbose_mode bool) *global {
	g := global{}
	g.victime_ip = ip_src
	g.victime_mac = mac_src
	g.serveur_ip = ip_target
	g.serveur_mac = mac_target
	g.attaquant_mac = attaquant_mac
	g.verbose_mode_activate = verbose_mode
	return &g
}

// func initFakeGlob() *global {
// 	// attaquant_ip := net.ParseIP("10.0.0.30")
// 	attaquant_mac, _ := net.ParseMAC("02:42:0a:00:00:0c")
// 	victime_ip := net.ParseIP("10.0.0.20")
// 	victime_mac, _ := net.ParseMAC("02:42:0A:00:00:0B")
// 	serveur_ip := net.ParseIP("10.0.0.10")
// 	serveur_mac, _ := net.ParseMAC("02:42:0A:00:00:0A")
// 	g := global{}
// 	g.victime_ip = victime_ip
// 	g.victime_mac = victime_mac
// 	g.serveur_ip = serveur_ip
// 	g.serveur_mac = serveur_mac
// 	g.attaquant_mac = attaquant_mac
// 	return &g
// }

func main() {
	var ip_src net.IP
	var mac_src net.HardwareAddr
	var ip_target net.IP
	var mac_target net.HardwareAddr
	var attaquant_mac net.HardwareAddr

	verboseMode := flag.Bool("v", false, "for sniff and show all packets")

	flag.Parse()
	argv := flag.Args()
	if !checkArgs(argv, &ip_src, &mac_src, &ip_target, &mac_target, &attaquant_mac) {
		return
	}

	global := initGlob(ip_src, mac_src, ip_target, mac_target, attaquant_mac, *verboseMode)
	// -------------------------------------------------------
	// global := initFakeGlob()
	// -------------------------------------------------------
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		signal.Reset()
		cancel()
		printRecuperation(10)
		launchRecuperationOneWay(global)
		launchRecuperationOtherWay(global)
		fmt.Println("CLEANING DONE")
		os.Exit(0)
	}()
	go launchPoisoning(global, ctx)
	go launchSniffing(global, ctx)

	for {
		// je bloque le processus principal
	}

}
