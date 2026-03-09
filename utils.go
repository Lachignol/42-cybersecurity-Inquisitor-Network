package main

import (
	"fmt"
	"os"
	"time"
)

func printPoisoning(count *int) {
	os.Stdout.Sync()
	dots := []string{"Poisoning", "Poisoning.", "Poisoning..", "Poisoning..."}

	fmt.Printf("\r%s", dots[*count])
	*count = (*count + 1) % len(dots)
}

func printSniffing(count *int) {
	os.Stdout.Sync()
	dots := []string{"Sniffing", "Sniffing.", "Sniffing..", "Sniffing..."}

	fmt.Printf("\r%s", dots[*count])
	*count = (*count + 1) % len(dots)
}

func printRecuperation(count int) {
	dots := []string{"Please waiting we starting ARP table restauration.", "Please waiting we starting ARP table restauration..", "Please waiting we starting ARP table restauration...", "Please waiting we starting ARP table restauration...."}
	for i := 0; i < count; i++ {
		os.Stdout.Sync()
		fmt.Printf("\r%s", dots[i])
		time.Sleep(1 * time.Second)
	}

}

func clearAllScreen() {
	fmt.Print("\033[H\033[2J")
}

func clearCurrentLine() {
	fmt.Print("\033[2K\033[1A")
}
