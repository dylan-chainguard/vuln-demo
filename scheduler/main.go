package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/robfig/cron/v3"
)

const (
	scriptsPath = "/scripts"
	reportsPath = "/reports"
)

// ScanJob represents a vulnerability scanning job
type ScanJob struct {
	Variant string
}

// RunScan executes the vulnerability scanning pipeline for a given variant
func (j *ScanJob) RunScan() error {
	log.Printf("========================================")
	log.Printf("Starting vulnerability scan for variant: %s", j.Variant)
	log.Printf("========================================")

	// Step 1: Scan vulnerabilities
	log.Printf("[%s] Step 1/2: Scanning images with Trivy and Grype...", j.Variant)
	scanCmd := exec.Command("/bin/bash", fmt.Sprintf("%s/scan-vulnerabilities.sh", scriptsPath), j.Variant)
	scanCmd.Stdout = os.Stdout
	scanCmd.Stderr = os.Stderr
	scanCmd.Env = os.Environ()

	if err := scanCmd.Run(); err != nil {
		return fmt.Errorf("scan failed for %s: %w", j.Variant, err)
	}
	log.Printf("[%s] ✅ Scan completed successfully", j.Variant)

	// Step 2: Load results to database
	log.Printf("[%s] Step 2/2: Loading results to database...", j.Variant)
	loadCmd := exec.Command("python3", fmt.Sprintf("%s/load-to-database.py", scriptsPath), "--variant", j.Variant)
	loadCmd.Stdout = os.Stdout
	loadCmd.Stderr = os.Stderr
	loadCmd.Env = os.Environ()

	if err := loadCmd.Run(); err != nil {
		return fmt.Errorf("database load failed for %s: %w", j.Variant, err)
	}
	log.Printf("[%s] ✅ Results loaded to database successfully", j.Variant)

	log.Printf("========================================")
	log.Printf("✅ Complete scan pipeline finished for variant: %s", j.Variant)
	log.Printf("========================================")

	return nil
}

// RunFullScanCycle scans both baseline and chainguard variants
func RunFullScanCycle() {
	log.Printf("===========================================")
	log.Printf("🚀 Starting full vulnerability scan cycle")
	log.Printf("Time: %s", time.Now().Format(time.RFC3339))
	log.Printf("===========================================")

	// Scan baseline variant
	baselineJob := &ScanJob{Variant: "baseline"}
	if err := baselineJob.RunScan(); err != nil {
		log.Printf("❌ Error scanning baseline: %v", err)
	}

	// Scan chainguard variant
	chainguardJob := &ScanJob{Variant: "chainguard"}
	if err := chainguardJob.RunScan(); err != nil {
		log.Printf("❌ Error scanning chainguard: %v", err)
	}

	log.Printf("===========================================")
	log.Printf("✅ Full scan cycle completed")
	log.Printf("Time: %s", time.Now().Format(time.RFC3339))
	log.Printf("===========================================")
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	log.Println("========================================")
	log.Println("Vulnerability Scanner Scheduler")
	log.Println("========================================")

	// Get schedule from environment variable, default to daily at 2 AM
	schedule := os.Getenv("SCAN_SCHEDULE")
	if schedule == "" {
		schedule = "0 2 * * *" // Daily at 2 AM UTC
	}
	log.Printf("Scan schedule: %s", schedule)

	// Check for immediate scan flag
	runImmediately := os.Getenv("RUN_IMMEDIATELY")
	if runImmediately == "true" {
		log.Println("RUN_IMMEDIATELY=true detected, starting scan now...")
		RunFullScanCycle()
	}

	// Set up cron scheduler
	c := cron.New(cron.WithLogger(cron.VerbosePrintfLogger(log.New(os.Stdout, "cron: ", log.LstdFlags))))

	_, err := c.AddFunc(schedule, RunFullScanCycle)
	if err != nil {
		log.Fatalf("Failed to add cron job: %v", err)
	}

	log.Printf("Scheduler started successfully")
	log.Printf("Next scan scheduled for: %s", c.Entries()[0].Next)
	log.Println("========================================")

	// Start the cron scheduler
	c.Start()

	// Keep the program running
	select {}
}
