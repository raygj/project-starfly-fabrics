package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestLogEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)

	event := &core.AuditEvent{
		Type:     "exchange",
		Action:   "token_issued",
		Subject:  "spiffe://example.com/web",
		Target:   "spiffe://example.com/api",
		Decision: "allowed",
		UnitID:   "unit-1",
	}

	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	var got core.AuditEvent
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal error: %v\nraw: %s", err, buf.String())
	}

	if got.Type != "exchange" {
		t.Errorf("Type = %q, want %q", got.Type, "exchange")
	}
	if got.Action != "token_issued" {
		t.Errorf("Action = %q, want %q", got.Action, "token_issued")
	}
	if got.Subject != "spiffe://example.com/web" {
		t.Errorf("Subject = %q, want %q", got.Subject, "spiffe://example.com/web")
	}
	if got.Target != "spiffe://example.com/api" {
		t.Errorf("Target = %q, want %q", got.Target, "spiffe://example.com/api")
	}
	if got.Decision != "allowed" {
		t.Errorf("Decision = %q, want %q", got.Decision, "allowed")
	}
	if got.UnitID != "unit-1" {
		t.Errorf("UnitID = %q, want %q", got.UnitID, "unit-1")
	}
}

func TestJSONStructure(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	ctx := context.Background()

	events := []*core.AuditEvent{
		{Type: "exchange", Action: "token_issued", Subject: "s1", Target: "t1", Decision: "allowed", UnitID: "u1"},
		{Type: "signal", Action: "event_received", Subject: "s2", Target: "t2", Decision: "allowed", UnitID: "u2"},
		{Type: "identity", Action: "identity_created", Subject: "s3", Target: "t3", Decision: "denied", UnitID: "u3"},
	}

	for _, e := range events {
		if err := logger.Log(ctx, e); err != nil {
			t.Fatalf("Log() error: %v", err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != len(events) {
		t.Fatalf("got %d lines, want %d", len(lines), len(events))
	}

	for i, line := range lines {
		var got core.AuditEvent
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Errorf("line %d: unmarshal error: %v", i, err)
			continue
		}
		if got.Type != events[i].Type {
			t.Errorf("line %d: Type = %q, want %q", i, got.Type, events[i].Type)
		}
		if got.Action != events[i].Action {
			t.Errorf("line %d: Action = %q, want %q", i, got.Action, events[i].Action)
		}
	}
}

func TestTimestampSet(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)

	event := &core.AuditEvent{
		Type:     "policy",
		Action:   "evaluated",
		Subject:  "sub",
		Target:   "tgt",
		Decision: "allowed",
		UnitID:   "u1",
	}

	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	var got core.AuditEvent
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if got.Timestamp.IsZero() {
		t.Error("Timestamp should be set when logged with zero value")
	}
}

func TestFlushOnClose(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)

	event := &core.AuditEvent{
		Type:     "admin",
		Action:   "config_changed",
		Subject:  "admin",
		Target:   "config",
		Decision: "allowed",
		UnitID:   "u1",
	}

	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatalf("Log() error: %v", err)
	}

	// Before Close, the buffer may not have been flushed to buf yet
	// (bufio.Writer buffers internally). After Close, it must be there.
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("buffer should contain data after Close()")
	}

	var got core.AuditEvent
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal error: %v\nraw: %s", err, buf.String())
	}
	if got.Action != "config_changed" {
		t.Errorf("Action = %q, want %q", got.Action, "config_changed")
	}
}

func TestConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	ctx := context.Background()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			event := &core.AuditEvent{
				Type:     "exchange",
				Action:   "token_issued",
				Subject:  "sub",
				Target:   "tgt",
				Decision: "allowed",
				UnitID:   "u1",
			}
			if err := logger.Log(ctx, event); err != nil {
				t.Errorf("Log() error: %v", err)
			}
		}()
	}

	wg.Wait()
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != numGoroutines {
		t.Errorf("got %d lines, want %d", len(lines), numGoroutines)
	}

	for i, line := range lines {
		var got core.AuditEvent
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Errorf("line %d: unmarshal error: %v", i, err)
		}
	}
}
