package lock

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// mockKMSClient implements kmsClient for testing.
type mockKMSClient struct {
	encryptFn func(ctx context.Context, input *kms.EncryptInput) (*kms.EncryptOutput, error)
	decryptFn func(ctx context.Context, input *kms.DecryptInput) (*kms.DecryptOutput, error)
}

func (m *mockKMSClient) Encrypt(ctx context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	return m.encryptFn(ctx, input)
}

func (m *mockKMSClient) Decrypt(ctx context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	return m.decryptFn(ctx, input)
}

// xorMock returns a mock that XORs plaintext with 0xAA for a reversible transform.
func xorMock() *mockKMSClient {
	xor := func(data []byte) []byte {
		out := make([]byte, len(data))
		for i, b := range data {
			out[i] = b ^ 0xAA
		}
		return out
	}
	return &mockKMSClient{
		encryptFn: func(_ context.Context, input *kms.EncryptInput) (*kms.EncryptOutput, error) {
			return &kms.EncryptOutput{CiphertextBlob: xor(input.Plaintext)}, nil
		},
		decryptFn: func(_ context.Context, input *kms.DecryptInput) (*kms.DecryptOutput, error) {
			return &kms.DecryptOutput{Plaintext: xor(input.CiphertextBlob)}, nil
		},
	}
}

func TestKMSLocker_Roundtrip(t *testing.T) {
	locker := newKMSLockerWithClient(xorMock(), "arn:aws:kms:us-east-1:123456789012:key/test-key")

	tests := []struct {
		name string
		data []byte
	}{
		{"text", []byte("hello, starfly")},
		{"empty", []byte{}},
		{"binary", []byte{0x00, 0xff, 0x00, 0xfe, 0x01}},
		{"json", []byte(`{"key":"value","n":42}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locked, err := locker.Lock(tt.data)
			if err != nil {
				t.Fatalf("Lock() error: %v", err)
			}

			unlocked, err := locker.Unlock(locked)
			if err != nil {
				t.Fatalf("Unlock() error: %v", err)
			}

			if !bytes.Equal(unlocked, tt.data) {
				t.Errorf("roundtrip mismatch: got %v, want %v", unlocked, tt.data)
			}
		})
	}
}

func TestKMSLocker_EncryptError(t *testing.T) {
	mock := &mockKMSClient{
		encryptFn: func(_ context.Context, _ *kms.EncryptInput) (*kms.EncryptOutput, error) {
			return nil, errors.New("kms unavailable")
		},
	}
	locker := newKMSLockerWithClient(mock, "arn:aws:kms:us-east-1:123456789012:key/test-key")

	_, err := locker.Lock([]byte("data"))
	if err == nil {
		t.Fatal("Lock() should return error when KMS fails")
	}
	if !errors.Is(err, errors.Unwrap(err)) && err.Error() == "" {
		t.Fatal("error should be non-empty")
	}
}

func TestKMSLocker_DecryptError(t *testing.T) {
	mock := &mockKMSClient{
		encryptFn: xorMock().encryptFn,
		decryptFn: func(_ context.Context, _ *kms.DecryptInput) (*kms.DecryptOutput, error) {
			return nil, errors.New("access denied")
		},
	}
	locker := newKMSLockerWithClient(mock, "arn:aws:kms:us-east-1:123456789012:key/test-key")

	_, err := locker.Unlock([]byte("ciphertext"))
	if err == nil {
		t.Fatal("Unlock() should return error when KMS fails")
	}
}

func TestKMSLocker_LockedDiffersFromInput(t *testing.T) {
	locker := newKMSLockerWithClient(xorMock(), "arn:aws:kms:us-east-1:123456789012:key/test-key")
	data := []byte("this should be encrypted")

	locked, err := locker.Lock(data)
	if err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	if bytes.Equal(locked, data) {
		t.Error("locked output should differ from input")
	}
}

func TestNewKMSLocker_MissingKeyID(t *testing.T) {
	_, err := NewKMSLocker(core.AWSKMSConfig{KeyID: "", Region: "us-east-1"})
	if err == nil {
		t.Fatal("NewKMSLocker() should fail with empty keyId")
	}
}
