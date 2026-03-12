package main

import (
	"errors"
	"fmt"
	"net"
)

func checkArgs(argv []string, ip_src *net.IP, mac_src *net.HardwareAddr, ip_target *net.IP, mac_target *net.HardwareAddr, attaquant_mac *net.HardwareAddr) bool {
	var err error
	if len(argv) != 5 {
		fmt.Printf("Usage:%s <IP-src> <MAC-src> <IP-target> <MAC-target> <MAC-attacker>", "inquisitor")
		return false
	}
	*ip_src, err = checkValidIpv4(argv[0])
	if err != nil {
		fmt.Println("ERROR: Not valid IP-src")
		return false
	}
	*ip_target, err = checkValidIpv4(argv[2])
	if err != nil {
		fmt.Println("ERROR: Not valid IP-target")
		return false
	}
	*mac_src, err = checkValidMacAddr(argv[1])
	if err != nil {
		fmt.Println("ERROR: Not valid Mac-src")
		return false
	}
	*mac_target, err = checkValidMacAddr(argv[3])
	if err != nil {
		fmt.Println("ERROR: Not valid Mac-target")
		return false
	}
	*attaquant_mac, err = checkValidMacAddr(argv[4])
	if err != nil {
		fmt.Println("ERROR: Not valid Mac-attack")
		return false
	}
	if argv[0] == argv[2] {
		fmt.Println("ERROR: IP-src and IP-target must be different")
		return false
	}
	if argv[1] == argv[3] {
		fmt.Println("ERROR: MAC-src and MAC-target must be different")
		return false
	}
	if argv[1] == argv[4] {
		fmt.Println("ERROR: MAC-src and MAC-attacker must be different")
		return false
	}
	if argv[3] == argv[4] {
		fmt.Println("ERROR: MAC-target and MAC-attacker must be different")
		return false
	}
	return true
}

func checkValidIpv4(ipToTest string) (net.IP, error) {
	ip := net.ParseIP(ipToTest)
	if ip == nil {
		return nil, errors.New("Not a valid ip")
	}
	if ip.To4() != nil {
		return ip, nil
	}
	return nil, errors.New("Not a valid ipv4")
}

func checkValidMacAddr(macAddrToTest string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(macAddrToTest)
	if err != nil {
		return nil, errors.New("Not a valid MAC")
	}
	return mac, nil
}
