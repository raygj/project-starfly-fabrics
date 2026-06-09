package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func testKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func TestSigningLogger_LogAndVerify(t *testing.T) {
	key := testKey()
	var buf bytes.Buffer
	logger := NewSigningLogger(&buf, key)

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

	var signed SignedAuditEvent
	if err := json.Unmarshal(buf.Bytes(), &signed); err != nil {
		t.Fatalf("unmarshal error: %v\nraw: %s", err, buf.String())
	}

	if signed.Signature == "" {
		t.Fatal("signature should not be empty")
	}
	if signed.Event.Type != "exchange" {
		t.Errorf("Type = %q, want %q", signed.Event.Type, "exchange")
	}

	if err := VerifySignedEvent(&signed, key); err != nil {
		t.Fatalf("VerifySignedEvent() error: %v", err)
	}
}

func TestSigningLogger_TamperedEvent(t *testing.T) {
	key := testKey()
	var buf bytes.Buffer
	logger := NewSigningLogger(&buf, key)

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

	var signed SignedAuditEvent
	if err := json.Unmarshal(buf.Bytes(), &signed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// Tamper with the event.
	signed.Event.Decision = "denied"

	err := VerifySignedEvent(&signed, key)
	if err == nil {
		t.Fatal("expected verification to fail for tampered event")
	}
	if !strings.Contains(err.Error(), "tampered") {
		t.Errorf("error should mention tampering, got: %v", err)
	}
}

func TestSigningLogger_WrongKey(t *testing.T) {
	key := testKey()
	wrongKey := testKey()

	var buf bytes.Buffer
	logger := NewSigningLogger(&buf, key)

	event := &core.AuditEvent{
		Type:     "identity",
		Action:   "identity_created",
		Subject:  "agent-1",
		Target:   "target",
		Decision: "allowed",
		UnitID:   "unit-1",
	}

	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	var signed SignedAuditEvent
	if err := json.Unmarshal(buf.Bytes(), &signed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	err := VerifySignedEvent(&signed, wrongKey)
	if err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestSigningLogger_TimestampSet(t *testing.T) {
	key := testKey()
	var buf bytes.Buffer
	logger := NewSigningLogger(&buf, key)

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

	var signed SignedAuditEvent
	if err := json.Unmarshal(buf.Bytes(), &signed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if signed.Event.Timestamp.IsZero() {
		t.Error("Timestamp should be set when logged with zero value")
	}

	// Signature should still verify with the set timestamp.
	if err := VerifySignedEvent(&signed, key); err != nil {
		t.Fatalf("VerifySignedEvent() error: %v", err)
	}
}

func TestSigningLogger_MultipleEvents(t *testing.T) {
	key := testKey()
	var buf bytes.Buffer
	logger := NewSigningLogger(&buf, key)
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
		var signed SignedAuditEvent
		if err := json.Unmarshal([]byte(line), &signed); err != nil {
			t.Errorf("line %d: unmarshal error: %v", i, err)
			continue
		}
		if err := VerifySignedEvent(&signed, key); err != nil {
			t.Errorf("line %d: verification failed: %v", i, err)
		}
		if signed.Event.Type != events[i].Type {
			t.Errorf("line %d: Type = %q, want %q", i, signed.Event.Type, events[i].Type)
		}
	}
}

func TestSigningLogger_ConcurrentWrites(t *testing.T) {
	key := testKey()
	var buf bytes.Buffer
	logger := NewSigningLogger(&buf, key)
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
		var signed SignedAuditEvent
		if err := json.Unmarshal([]byte(line), &signed); err != nil {
			t.Errorf("line %d: unmarshal error: %v", i, err)
			continue
		}
		if err := VerifySignedEvent(&signed, key); err != nil {
			t.Errorf("line %d: verification failed: %v", i, err)
		}
	}
}

func TestSigningLogger_InvalidSignatureHex(t *testing.T) {
	key := testKey()
	signed := &SignedAuditEvent{
		Event: &core.AuditEvent{
			Type:     "exchange",
			Action:   "token_issued",
			Subject:  "sub",
			Target:   "tgt",
			Decision: "allowed",
			UnitID:   "u1",
		},
		Signature: "not-valid-hex!!!",
	}

	err := VerifySignedEvent(signed, key)
	if err == nil {
		t.Fatal("expected error for invalid hex signature")
	}
}
