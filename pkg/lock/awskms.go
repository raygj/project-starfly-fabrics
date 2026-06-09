package lock

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// Compile-time check that KMSLocker implements core.Locker.
var _ core.Locker = (*KMSLocker)(nil)

// kmsClient abstracts the AWS KMS API methods used by KMSLocker, enabling
// unit tests with a mock implementation.
type kmsClient interface {
	Encrypt(ctx context.Context, input *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, input *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// KMSLocker implements core.Locker using AWS KMS for envelope encryption.
// The signing key never leaves the KMS boundary.
type KMSLocker struct {
	client kmsClient
	keyID  string
}

// NewKMSLocker creates a KMSLocker using the AWS default credential chain.
func NewKMSLocker(cfg core.AWSKMSConfig) (*KMSLocker, error) {
	if cfg.KeyID == "" {
		return nil, fmt.Errorf("awskms: keyId must not be empty")
	}

	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("awskms: loading AWS config: %w", err)
	}

	return &KMSLocker{
		client: kms.NewFromConfig(awsCfg),
		keyID:  cfg.KeyID,
	}, nil
}

// newKMSLockerWithClient creates a KMSLocker with a pre-built client (for testing).
func newKMSLockerWithClient(client kmsClient, keyID string) *KMSLocker {
	return &KMSLocker{client: client, keyID: keyID}
}

// Lock encrypts data using the configured KMS key.
func (k *KMSLocker) Lock(data []byte) ([]byte, error) {
	out, err := k.client.Encrypt(context.Background(), &kms.EncryptInput{
		KeyId:     &k.keyID,
		Plaintext: data,
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: encrypt: %w", err)
	}
	return out.CiphertextBlob, nil
}

// Unlock decrypts data using KMS (the key ID is encoded in the ciphertext blob).
func (k *KMSLocker) Unlock(data []byte) ([]byte, error) {
	out, err := k.client.Decrypt(context.Background(), &kms.DecryptInput{
		CiphertextBlob: data,
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: decrypt: %w", err)
	}
	return out.Plaintext, nil
}
