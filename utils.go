package main

import (
	"fmt"
	"os"
	"time"
)

func printPoisoning(duration int) {
	dots := []string{"Initialize Poisoning", "Initialize Poisoning.", "Initialize Poisoning..", "Initialize Poisoning..."}
	count := 0
	for i := 0; i < duration; i++ {
		os.Stdout.Sync()
		fmt.Printf("\r%s", dots[count])
		count = (count + 1) % len(dots)
		i++
		time.Sleep(1 * time.Second)
	}
	os.Stdout.Sync()
	clearCurrentLine()
}

func printSniffing(duration int) {
	dots := []string{"Initialize Sniffing", "Initialize Sniffing.", "Initialize Sniffing..", "Initialize Sniffing..."}
	count := 0
	for i := 0; i < duration; i++ {
		os.Stdout.Sync()
		fmt.Printf("\r%s", dots[count])
		count = (count + 1) % len(dots)
		i++
		time.Sleep(1 * time.Second)
	}
	os.Stdout.Sync()
	clearCurrentLine()

}

func printRecuperation(duration int) {
	dots := []string{"Please waiting we starting ARP table restauration.", "Please waiting we starting ARP table restauration..", "Please waiting we starting ARP table restauration...", "Please waiting we starting ARP table restauration...."}
	count := 0
	for i := 0; i < duration; i++ {
		os.Stdout.Sync()
		fmt.Printf("\r%s", dots[count])
		count = (count + 1) % len(dots)
		i++
		time.Sleep(1 * time.Second)
	}
	os.Stdout.Sync()
	clearCurrentLine()
}

func clearAllScreen() {
	fmt.Print("\033[H\033[2J")
}

func clearCurrentLine() {
	fmt.Print("\033[2K\r")
}
