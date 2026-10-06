package analyzer

import "github.com/ethan-j44/go-security-log-analyzer/models"

type AnalysisResult struct {
	TotalEvents       int
	SuccessfulLogins  int
	FailedLogins      int
	FailuresByIP      map[string]int
	SuspiciousIPs     map[string]int
}



func Analyze(events []models.SecurityEvent, threshold int) AnalysisResult {

	result := AnalysisResult{
		FailuresByIP:  make(map[string]int),
		SuspiciousIPs: make(map[string]int),
	}

	for _, event := range events {

		result.TotalEvents++

		if event.Success {
			result.SuccessfulLogins++
		} else {
			result.FailedLogins++
			result.FailuresByIP[event.SourceIP]++
		}
	}

	for ip, failures := range result.FailuresByIP {
		if failures >= threshold {
			result.SuspiciousIPs[ip] = failures
		}
	}

	return result
}