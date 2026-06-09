package lock

import (
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestNew_Dev(t *testing.T) {
	locker, err := New(core.LockConfig{Type: "dev"})
	if err != nil {
		t.Fatalf("New(dev): %v", err)
	}
	if _, ok := locker.(*DevLocker); !ok {
		t.Error("expected *DevLocker")
	}
}

func TestNewKMSLocker_WithRegion(t *testing.T) {
	locker, err := NewKMSLocker(core.AWSKMSConfig{
		KeyID:  "arn:aws:kms:us-east-1:123456789012:key/test",
		Region: "us-west-2",
	})
	if err != nil {
		t.Fatalf("NewKMSLocker with region: %v", err)
	}
	if locker == nil {
		t.Fatal("expected non-nil locker")
	}
}

func TestNewKMSLocker_DefaultRegion(t *testing.T) {
	locker, err := NewKMSLocker(core.AWSKMSConfig{
		KeyID: "arn:aws:kms:us-east-1:123456789012:key/test",
	})
	if err != nil {
		t.Fatalf("NewKMSLocker default region: %v", err)
	}
	if locker == nil {
		t.Fatal("expected non-nil locker")
	}
}

func TestNew_AWSKMSMissingKey(t *testing.T) {
	_, err := New(core.LockConfig{
		Type:   "awskms",
		AWSKMS: core.AWSKMSConfig{KeyID: ""},
	})
	if err == nil {
		t.Error("expected error for empty KMS key")
	}
}

func TestNew_GCPNotImplemented(t *testing.T) {
	_, err := New(core.LockConfig{Type: "gcpckms"})
	if err == nil {
		t.Error("expected error for unimplemented gcpckms")
	}
}

func TestNew_AzureNotImplemented(t *testing.T) {
	_, err := New(core.LockConfig{Type: "azurekeyvault"})
	if err == nil {
		t.Error("expected error for unimplemented azurekeyvault")
	}
}

func TestNew_UnknownType(t *testing.T) {
	_, err := New(core.LockConfig{Type: "magic"})
	if err == nil {
		t.Error("expected error for unknown lock type")
	}
}

func TestNewFromTypeAndKey_Dev(t *testing.T) {
	locker, err := NewFromTypeAndKey("dev", "")
	if err != nil {
		t.Fatalf("NewFromTypeAndKey(dev): %v", err)
	}
	if _, ok := locker.(*DevLocker); !ok {
		t.Error("expected *DevLocker")
	}
}

func TestNewFromTypeAndKey_AWSKMSMissingKey(t *testing.T) {
	_, err := NewFromTypeAndKey("awskms", "")
	if err == nil {
		t.Error("expected error for empty KMS key")
	}
}

func TestNewFromTypeAndKey_UnknownType(t *testing.T) {
	_, err := NewFromTypeAndKey("unknown", "key")
	if err == nil {
		t.Error("expected error for unsupported lock type")
	}
}
