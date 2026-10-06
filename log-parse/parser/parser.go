package parser

import (
	"regexp"
	"strings"
	"time"

	"github.com/ethan-j44/go-security-log-analyzer/models"
)

var failedLoginRegex = regexp.MustCompile(
	`^(\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for (?:invalid user )?(\S+) from ([\d.]+)`,
)

var successfulLoginRegex = regexp.MustCompile(
	`^(\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted password for (\S+) from ([\d.]+)`,
)

func ParseLine(line string) (models.SecurityEvent, bool) {

	if strings.Contains(line, "Failed password") {
		matches := failedLoginRegex.FindStringSubmatch(line)

		if len(matches) == 4 {
			timestamp, _ := time.Parse("Jan 2 15:04:05", matches[1])

			return models.SecurityEvent{
				Timestamp: timestamp,
				EventType: "SSH_LOGIN_FAILURE",
				Username:  matches[2],
				SourceIP:  matches[3],
				Service:   "ssh",
				Success:   false,
				RawLog:    line,
			}, true
		}
	}

	if strings.Contains(line, "Accepted password") {
		matches := successfulLoginRegex.FindStringSubmatch(line)

		if len(matches) == 4 {
			timestamp, _ := time.Parse("Jan 2 15:04:05", matches[1])

			return models.SecurityEvent{
				Timestamp: timestamp,
				EventType: "SSH_LOGIN_SUCCESS",
				Username:  matches[2],
				SourceIP:  matches[3],
				Service:   "ssh",
				Success:   true,
				RawLog:    line,
			}, true
		}
	}

	return models.SecurityEvent{}, false
}
