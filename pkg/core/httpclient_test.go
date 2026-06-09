package core

import "testing"

func TestNewDefaultHTTPClient(t *testing.T) {
	c := NewDefaultHTTPClient()
	if c == nil {
		t.Fatal("NewDefaultHTTPClient returned nil")
	}
	if c.Timeout != DefaultHTTPTimeout {
		t.Errorf("timeout = %v, want %v", c.Timeout, DefaultHTTPTimeout)
	}
}

func TestNewDefaultHTTPClientReturnsDistinctInstances(t *testing.T) {
	a := NewDefaultHTTPClient()
	b := NewDefaultHTTPClient()
	if a == b {
		t.Error("NewDefaultHTTPClient should return distinct instances")
	}
}
