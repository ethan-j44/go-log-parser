package models

import "time"

type SecurityEvent struct {
	Timestamp time.Time
	EventType string
	Username  string
	SourceIP  string
	Service   string
	Success   bool
	RawLog    string
}