package lock

import (
	"bytes"
	"testing"
)

func TestDevLocker_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"text", []byte("hello, starfly")},
		{"empty", []byte{}},
		{"binary with nulls", []byte{0x00, 0xff, 0x00, 0xfe, 0x01}},
		{"json payload", []byte(`{"key":"value","n":42}`)},
		{"single byte", []byte{0x42}},
	}

	s := &DevLocker{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locked, err := s.Lock(tt.data)
			if err != nil {
				t.Fatalf("Lock() error: %v", err)
			}

			unlocked, err := s.Unlock(locked)
			if err != nil {
				t.Fatalf("Unlock() error: %v", err)
			}

			if !bytes.Equal(unlocked, tt.data) {
				t.Errorf("roundtrip mismatch: got %v, want %v", unlocked, tt.data)
			}
		})
	}
}

func TestDevLocker_LockedDiffersFromInput(t *testing.T) {
	s := &DevLocker{}
	data := []byte("this should be encoded")

	locked, err := s.Lock(data)
	if err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	if bytes.Equal(locked, data) {
		t.Error("locked output should differ from input")
	}
}

func TestDevLocker_UnlockRejectsInvalidBase64(t *testing.T) {
	s := &DevLocker{}

	_, err := s.Unlock([]byte("not-valid-base64!!!"))
	if err == nil {
		t.Error("Unlock() should reject invalid base64")
	}
}
