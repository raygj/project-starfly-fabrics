package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// heartbeatInterval is the interval between SSE heartbeat comments.
// Exported as a variable so tests can override it.
var heartbeatInterval = 5 * time.Second

// HandleEvents serves Server-Sent Events for real-time fabric events.
// Supports query param ?types=exchange,caep to filter event types.
// An empty or absent types param means all event types are streamed.
func (s *Server) HandleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.devMode && !s.requireBearerAuth(w, r) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Parse optional type filter.
	typeFilter := make(map[string]struct{})
	if raw := r.URL.Query().Get("types"); raw != "" {
		for _, t := range strings.Split(raw, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				typeFilter[t] = struct{}{}
			}
		}
	}

	// Set SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Send an initial comment so browsers render the connection immediately
	// rather than buffering until the first real event.
	_, _ = fmt.Fprintf(w, ": connected to %s luminescence stream\n\n", s.unitID)
	flusher.Flush()

	// Subscribe to the broadcaster.
	ch := s.broadcaster.Subscribe()
	defer s.broadcaster.Unsubscribe(ch)

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			// Apply type filter.
			if len(typeFilter) > 0 {
				if _, match := typeFilter[event.Type]; !match {
					continue
				}
			}
			data, err := json.Marshal(event)
			if err != nil {
				slog.Error("failed to marshal event", "error", err)
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
