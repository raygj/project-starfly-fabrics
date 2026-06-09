package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Broadcaster tests ---

func TestEventBroadcaster_SendsToSubscribers(t *testing.T) {
	b := NewEventBroadcaster()
	ch1 := b.Subscribe()
	ch2 := b.Subscribe()

	event := FabricEvent{
		ID:   "evt-1",
		Type: "exchange",
	}
	b.Broadcast(event)

	select {
	case got := <-ch1:
		if got.ID != "evt-1" {
			t.Errorf("ch1: got ID %q, want %q", got.ID, "evt-1")
		}
	case <-time.After(time.Second):
		t.Fatal("ch1: timed out waiting for event")
	}

	select {
	case got := <-ch2:
		if got.ID != "evt-1" {
			t.Errorf("ch2: got ID %q, want %q", got.ID, "evt-1")
		}
	case <-time.After(time.Second):
		t.Fatal("ch2: timed out waiting for event")
	}

	b.Unsubscribe(ch1)
	b.Unsubscribe(ch2)
}

func TestEventBroadcaster_Unsubscribe(t *testing.T) {
	b := NewEventBroadcaster()
	ch := b.Subscribe()
	b.Unsubscribe(ch)

	// Channel should be closed.
	_, ok := <-ch
	if ok {
		t.Error("expected channel to be closed after unsubscribe")
	}

	// Broadcast should not panic with no subscribers.
	b.Broadcast(FabricEvent{ID: "evt-2"})
}

func TestEventBroadcaster_SlowClient(t *testing.T) {
	b := &EventBroadcaster{
		subscribers: make(map[chan FabricEvent]struct{}),
		bufferSize:  2, // tiny buffer
	}
	slow := b.Subscribe()
	fast := b.Subscribe()

	// Fill the slow client's buffer.
	for i := 0; i < 5; i++ {
		b.Broadcast(FabricEvent{ID: fmt.Sprintf("evt-%d", i)})
	}

	// Fast client should have received 2 events (buffer size).
	received := 0
	for {
		select {
		case <-fast:
			received++
		default:
			goto done
		}
	}
done:
	if received != 2 {
		t.Errorf("fast client received %d events, want 2", received)
	}

	// Slow client should also have 2 (buffer was full, extras dropped).
	received = 0
	for {
		select {
		case <-slow:
			received++
		default:
			goto done2
		}
	}
done2:
	if received != 2 {
		t.Errorf("slow client received %d events, want 2", received)
	}

	b.Unsubscribe(slow)
	b.Unsubscribe(fast)
}

func TestEventBroadcaster_SubscriberCount(t *testing.T) {
	b := NewEventBroadcaster()

	if got := b.SubscriberCount(); got != 0 {
		t.Fatalf("initial count = %d, want 0", got)
	}

	ch1 := b.Subscribe()
	ch2 := b.Subscribe()

	if got := b.SubscriberCount(); got != 2 {
		t.Fatalf("after 2 subscribes = %d, want 2", got)
	}

	b.Unsubscribe(ch1)
	if got := b.SubscriberCount(); got != 1 {
		t.Fatalf("after 1 unsub = %d, want 1", got)
	}

	b.Unsubscribe(ch2)
	if got := b.SubscriberCount(); got != 0 {
		t.Fatalf("after 2 unsubs = %d, want 0", got)
	}
}

func TestEventBroadcaster_ConcurrentBroadcast(t *testing.T) {
	b := NewEventBroadcaster()
	ch := b.Subscribe()

	const goroutines = 10
	const eventsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				b.Broadcast(FabricEvent{
					ID:   fmt.Sprintf("g%d-evt-%d", id, i),
					Type: "exchange",
				})
			}
		}(g)
	}
	wg.Wait()

	// Drain the channel; we should have received all events since
	// buffer (1000) > total events (500).
	received := 0
	for {
		select {
		case <-ch:
			received++
		default:
			goto done3
		}
	}
done3:
	total := goroutines * eventsPerGoroutine
	if received != total {
		t.Errorf("received %d events, want %d", received, total)
	}
	b.Unsubscribe(ch)
}

// --- SSE handler tests ---

func TestHandleEvents_StreamsEvents(t *testing.T) {
	s := newTestServer()
	ts := httptest.NewServer(s.router)
	defer ts.Close()

	// Connect to the SSE endpoint.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want %q", ct, "text/event-stream")
	}

	// Wait until the SSE handler has subscribed to the broadcaster.
	// Without this, the broadcast can race ahead of Subscribe().
	deadline := time.Now().Add(2 * time.Second)
	for s.broadcaster.SubscriberCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for SSE handler to subscribe")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Broadcast an event.
	s.broadcaster.Broadcast(FabricEvent{
		ID:     "evt-sse-1",
		Type:   "exchange",
		Result: "ok",
	})

	// Read the first SSE data line.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			payload := strings.TrimPrefix(line, "data: ")
			var got FabricEvent
			if err := json.Unmarshal([]byte(payload), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.ID != "evt-sse-1" {
				t.Errorf("event ID = %q, want %q", got.ID, "evt-sse-1")
			}
			return // success
		}
	}
	t.Fatal("never received SSE data line")
}

func TestHandleEvents_TypeFilter(t *testing.T) {
	s := newTestServer()
	ts := httptest.NewServer(s.router)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/events?types=exchange", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Wait until the SSE handler has subscribed to the broadcaster.
	// Without this, the broadcast can race ahead of Subscribe().
	deadline := time.Now().Add(2 * time.Second)
	for s.broadcaster.SubscriberCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for SSE handler to subscribe")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Broadcast a caep event (should be filtered out) then an exchange event.
	s.broadcaster.Broadcast(FabricEvent{ID: "caep-1", Type: "caep", Result: "ok"})
	s.broadcaster.Broadcast(FabricEvent{ID: "exch-1", Type: "exchange", Result: "ok"})

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			payload := strings.TrimPrefix(line, "data: ")
			var got FabricEvent
			if err := json.Unmarshal([]byte(payload), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Type == "caep" {
				t.Error("received caep event despite type filter for exchange only")
			}
			if got.ID == "exch-1" {
				return // success — got the expected filtered event
			}
		}
	}
	t.Fatal("never received filtered exchange event")
}

func TestHandleEvents_Heartbeat(t *testing.T) {
	// Override heartbeat interval for test speed.
	old := heartbeatInterval
	heartbeatInterval = 50 * time.Millisecond
	defer func() { heartbeatInterval = old }()

	s := newTestServer()
	ts := httptest.NewServer(s.router)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Wait until the SSE handler has subscribed to the broadcaster.
	deadline := time.Now().Add(2 * time.Second)
	for s.broadcaster.SubscriberCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for SSE handler to subscribe")
		}
		time.Sleep(5 * time.Millisecond)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == ": heartbeat" {
			return // success
		}
	}
	t.Fatal("never received heartbeat comment")
}

func TestHandleEvents_ClientDisconnect(t *testing.T) {
	// Use a short heartbeat so the handler writes frequently; when the
	// client disconnects the next heartbeat write will fail, causing the
	// handler to return promptly even if ctx.Done() propagation is delayed.
	old := heartbeatInterval
	heartbeatInterval = 50 * time.Millisecond
	defer func() { heartbeatInterval = old }()

	s := newTestServer()
	ts := httptest.NewServer(s.router)
	defer ts.Close()

	// Use a timeout context as a safety net so the test cannot hang
	// indefinitely if the server-side handler fails to detect the disconnect.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Wrap the timeout context with a manual cancel so we can simulate
	// an explicit client disconnect while still having the outer timeout.
	clientCtx, clientCancel := context.WithCancel(ctx)

	req, err := http.NewRequestWithContext(clientCtx, http.MethodGet, ts.URL+"/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	// Wait until the SSE handler has subscribed to the broadcaster.
	// Without this, the subscriber count check below races with Subscribe().
	deadline := time.Now().Add(2 * time.Second)
	for s.broadcaster.SubscriberCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for SSE handler to subscribe")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Record initial subscriber count.
	if got := s.broadcaster.SubscriberCount(); got != 1 {
		t.Fatalf("subscriber count = %d, want 1", got)
	}

	// Cancel the client context (simulates disconnect).
	clientCancel()
	_ = resp.Body.Close()

	// Wait for the handler to unsubscribe.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.broadcaster.SubscriberCount() == 0 {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("subscriber count = %d after disconnect, want 0", s.broadcaster.SubscriberCount())
}
