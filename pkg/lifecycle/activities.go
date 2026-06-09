package lifecycle

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// Activities holds references to Starfly core interfaces and exposes
// them as Temporal activity methods. All interaction with the exchange
// engine, signal engine, and revocation index flows through here.
type Activities struct {
	exchanger  core.TokenExchanger
	transmitter core.SignalTransmitter
	revocation core.RevocationIndex
	unitID     string
}

// NewActivities creates the shared activity set for lifecycle workflows.
func NewActivities(
	exchanger core.TokenExchanger,
	transmitter core.SignalTransmitter,
	revocation core.RevocationIndex,
	unitID string,
) *Activities {
	return &Activities{
		exchanger:   exchanger,
		transmitter: transmitter,
		revocation:  revocation,
		unitID:      unitID,
	}
}

// MintExecutionScopedToken performs a token exchange with an execution scope
// bound to a specific lifecycle action. Returns the signed JWT.
func (a *Activities) MintExecutionScopedToken(ctx context.Context, scope core.ExecutionScope) (string, error) {
	slog.Debug("lifecycle: minting execution-scoped token",
		"method", scope.Method,
		"uri", scope.URI,
	)

	resp, err := a.exchanger.Exchange(ctx, &core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     "urn:starfly:lifecycle-worker:" + a.unitID,
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:         "urn:starfly:internal",
		ExecutionScope:   &scope,
	})
	if err != nil {
		return "", fmt.Errorf("lifecycle: minting execution-scoped token: %w", err)
	}

	return resp.AccessToken, nil
}

// EmitLifecycleSignal transmits an SSF event for a lifecycle action.
func (a *Activities) EmitLifecycleSignal(ctx context.Context, eventType string, subjectID string, claims map[string]interface{}) error {
	slog.Info("lifecycle: emitting signal",
		"event_type", eventType,
		"subject", subjectID,
	)

	event := &core.SecurityEvent{
		Issuer:   a.unitID,
		JTI:      fmt.Sprintf("lifecycle-%s-%d", eventType, time.Now().UnixNano()),
		IssuedAt: time.Now().Unix(),
		Audience: "urn:starfly:fabric",
		SubjectID: &core.SubjectIdentifier{
			Format: "uri",
			URI:    subjectID,
		},
		Events: map[string]map[string]interface{}{
			eventType: claims,
		},
	}

	return a.transmitter.TransmitEvent(ctx, event)
}

// RevokeCredential marks a subject as revoked in the revocation index.
func (a *Activities) RevokeCredential(ctx context.Context, req RevokeRequest) error {
	slog.Info("lifecycle: revoking credential",
		"subject_id", req.SubjectID,
		"reason", req.Reason,
	)

	expiresAt := time.Now().Add(req.ExpiresIn)
	if req.ExpiresIn == 0 {
		expiresAt = time.Now().Add(24 * time.Hour)
	}

	return a.revocation.Revoke(ctx, req.SubjectID, req.Reason, expiresAt)
}

// CheckRevocationStatus checks whether a subject is currently revoked.
func (a *Activities) CheckRevocationStatus(ctx context.Context, subjectID string) (*RevocationResult, error) {
	entry, err := a.revocation.IsRevoked(ctx, subjectID)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: checking revocation: %w", err)
	}

	if entry == nil {
		return &RevocationResult{Revoked: false}, nil
	}

	return &RevocationResult{
		Revoked:   true,
		Reason:    entry.Reason,
		RevokedAt: entry.RevokedAt,
	}, nil
}
