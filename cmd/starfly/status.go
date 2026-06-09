package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/starfly-fabrics/starfly/pkg/cli"
)

// runStatus implements `starfly status` — fetches the /metrics endpoint
// and prints a human-readable or JSON fabric status summary.
func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	var (
		jsonOutput bool
		endpoint   string
	)
	fs.BoolVar(&jsonOutput, "json", false, "output as JSON")
	fs.StringVar(&endpoint, "endpoint", "http://localhost:9090/metrics", "metrics endpoint URL")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
  starfly status [flags]

Fetches the Starfly /metrics endpoint and displays fabric status.

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	status, err := cli.ReadMetrics(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return 1
	}

	if jsonOutput {
		data, jsonErr := cli.FormatStatusJSON(status)
		if jsonErr != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", jsonErr)
			return 1
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(cli.FormatStatus(status))
	}

	return 0
}
