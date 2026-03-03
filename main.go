package main

import "fmt"

func main() {
	var ip_src string
	var mac_src string
	var ip_target string
	var mac_target string

	if !setup(&ip_src, &mac_src, &ip_target, &mac_target) {
		return
	}
	fmt.Println("args ok")

}
