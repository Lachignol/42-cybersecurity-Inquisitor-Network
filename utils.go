package main

import "fmt"

func printPoisoning(count *int) {

	if *count == 0 {
		fmt.Println("Poisoning.")
		*count++
		return
	}
	if *count == 1 {
		fmt.Println("Poisoning..")
		*count++
		return
	}

	if *count == 2 {
		fmt.Println("Poisoning...")
		*count = 0
		return
	}
}

func printSniffing(count *int) {

	if *count == 0 {
		fmt.Println("Sniffing.")
		*count++
		return
	}
	if *count == 1 {
		fmt.Println("Sniffing..")
		*count++
		return
	}

	if *count == 2 {
		fmt.Println("Sniffing...")
		*count = 0
		return
	}
}
