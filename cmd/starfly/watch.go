package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/api"
	"github.com/starfly-fabrics/starfly/pkg/cli"
)

// runWatch implements `starfly watch` — live event stream from the fabric.
func runWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	var (
		endpoint  string
		typesList string
	)
	fs.StringVar(&endpoint, "endpoint", "http://localhost:8693/v1/events", "SSE endpoint URL")
	fs.StringVar(&typesList, "types", "", "comma-separated event types to filter (e.g. exchange,caep)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
  starfly watch [flags]

Streams live fabric events as a colored terminal feed.

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	// Build request URL with type filter.
	url := endpoint
	if typesList != "" {
		url += "?types=" + typesList
	}

	// Set up Ctrl+C handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		slog.Error("building request", "error", err)
		return 1
	}
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{Timeout: 0} // No timeout for SSE.
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("connecting to event stream", "error", err, "url", url)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		slog.Error("unexpected status", "status", resp.StatusCode)
		return 1
	}

	fmt.Fprintf(os.Stderr, "Connected to %s — streaming events (Ctrl+C to stop)\n\n", endpoint)

	// Read SSE lines in a goroutine.
	eventCh := make(chan api.FabricEvent)
	errCh := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")
			if data == "" || data == ":heartbeat" {
				continue
			}

			var event api.FabricEvent
			if err := json.Unmarshal([]byte(data), &event); err != nil {
				continue // Skip malformed events.
			}
			eventCh <- event
		}
		errCh <- scanner.Err()
	}()

	for {
		select {
		case event := <-eventCh:
			fmt.Println(FormatEvent(event))
		case err := <-errCh:
			if err != nil {
				slog.Error("stream error", "error", err)
				return 1
			}
			fmt.Fprintf(os.Stderr, "\nStream closed by server.\n")
			return 0
		case <-sigCh:
			fmt.Fprintf(os.Stderr, "\nDisconnected.\n")
			return 0
		}
	}
}

// FormatEvent formats a FabricEvent as a single terminal line.
// Format: "14:32:07.123  exchange  k8s-sa → payments.prod/sa/api-gw  1.2ms  ✓"
func FormatEvent(e api.FabricEvent) string {
	ts := e.Timestamp
	if t, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
		ts = t.Format("15:04:05.000")
	}

	// Event type, padded.
	eventType := fmt.Sprintf("%-9s", e.Type)

	// Subject and target.
	target := e.Subject
	if e.Target != "" {
		target = e.Subject + " → " + e.Target
	}
	// Truncate long targets for terminal display.
	if len(target) > 50 {
		target = target[:47] + "..."
	}
	target = fmt.Sprintf("%-50s", target)

	// Duration.
	dur := ""
	if e.Duration > 0 {
		dur = fmt.Sprintf("%.1fms", e.Duration)
	}
	dur = fmt.Sprintf("%-8s", dur)

	// Result indicator.
	var result string
	switch e.Result {
	case "ok":
		result = cli.ColorGreen("✓")
	case "denied":
		result = cli.ColorRed("✗")
	case "error":
		result = cli.ColorRed("!")
	default:
		result = "·"
	}

	// Color the event type.
	switch e.Type {
	case "exchange":
		eventType = cli.ColorGreen(eventType)
	case "denial":
		eventType = cli.ColorRed(eventType)
	case "caep":
		eventType = cli.ColorYellow(eventType)
	case "signal":
		eventType = cli.ColorYellow(eventType)
	case "soul":
		eventType = cli.ColorDim(eventType)
	}

	return fmt.Sprintf("%s  %s  %s  %s  %s", cli.ColorDim(ts), eventType, target, dur, result)
}
