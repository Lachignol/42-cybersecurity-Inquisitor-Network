package main

import (
	"fmt"
	"os"
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
