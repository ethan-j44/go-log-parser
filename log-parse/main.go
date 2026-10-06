package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/ethan-j44/go-security-log-analyzer/parser"
)

func main() {
	file, err := os.Open("testdata/auth.log")
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		event, ok := parser.ParseLine(line)

		if ok {
			fmt.Printf(
				"Event: %-20s User: %-15s IP: %s\n",
				event.EventType,
				event.Username,
				event.SourceIP,
			)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading log file:", err)
	}
}