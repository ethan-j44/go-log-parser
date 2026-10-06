package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/ethan-j44/go-security-log-analyzer/analyzer"
	"github.com/ethan-j44/go-security-log-analyzer/models"
	"github.com/ethan-j44/go-security-log-analyzer/parser"
)

func main() {
	file, err := os.Open("testdata/auth.log")
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	defer file.Close()

	var events []models.SecurityEvent

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		event, ok := parser.ParseLine(line)

		if ok {
			events = append(events, event)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading log file:", err)
		return
	}
	// run the analyzer...?

	result := analyzer.Analyze(events, 5)

	fmt.Println("=== Authentication Summary ===")
	fmt.Println("Total events:", result.TotalEvents)
	fmt.Println("Successful logins:", result.SuccessfulLogins)
	fmt.Println("Failed logins:", result.FailedLogins)

	fmt.Println("\n=== Failed Logins by IP ===")

	for ip, count := range result.FailuresByIP {
		fmt.Printf("%-20s %d failures\n", ip, count)
	}

	fmt.Println("\n=== Security Alerts ===")

	for ip, count := range result.SuspiciousIPs {
		fmt.Printf(
			"[HIGH] Possible brute-force attack from %s (%d failures)\n",
			ip,
			count,
		)
	}
}