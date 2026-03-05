package main

import (
	"fmt"
	"net"
	"os"
)

func setup(ip_src *string, mac_src *string, ip_target *string, mac_target *string) bool {
	if !setArgs(ip_src, mac_src, ip_target, mac_target) ||
		!checkArgs(*ip_src, *mac_src, *ip_target, *mac_target) {
		return false
	}
	return true
}

func setArgs(ip_src *string, mac_src *string, ip_target *string, mac_target *string) bool {
	argv := os.Args
	if len(argv) != 5 {
		fmt.Printf("Usage:%s <IP-src> <MAC-src> <IP-target> <MAC-target>", argv[0])
		return false
	}
	*ip_src = argv[1]
	*mac_src = argv[2]
	*ip_target = argv[3]
	*mac_target = argv[4]
	return true
}

func checkArgs(ip_src string, mac_src string, ip_target string, mac_target string) bool {
	if !checkValidIpv4(ip_src) {
		fmt.Println("ERROR: Not valid IP-src")
		return false
	}
	if !checkValidIpv4(ip_target) {
		fmt.Println("ERROR: Not valid IP-target")
		return false
	}
	if !checkValidMacAddr(mac_src) {
		fmt.Println("ERROR: Not valid Mac-src")
		return false
	}
	if !checkValidMacAddr(mac_target) {
		fmt.Println("ERROR: Not valid Mac-target")
		return false
	}
	if ip_src == ip_target {
		fmt.Println("ERROR: IP-src and IP-target must be different")
		return false
	}
	if mac_src == mac_target {
		fmt.Println("ERROR: MAC-src and MAC-target must be different")
		return false
	}
	return true
}

func checkValidIpv4(ipToTest string) bool {
	ip := net.ParseIP(ipToTest)
	if ip == nil {
		return false
	}
	return ip.To4() != nil
}

func checkValidMacAddr(macAddrToTest string) bool {
	_, err := net.ParseMAC(macAddrToTest)
	if err == nil {
		return false
	}
	return true
}
