// Package toolcall provides the universal tool-call verification layer (ADR-0022).
//
// Middleware implements http.Handler wrapping that:
//  1. Runs all registered adapters in parallel to extract a ToolCallRequest.
//  2. Picks the highest-confidence match (ties broken by adapter order).
//  3. Passes the request to the Verifier.
//  4. Injects the resulting VerifiedIdentity into the request context.
//  5. Rejects with the winning adapter's FormatError on any failure.
package toolcall

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"time"
)

type contextKey int

const identityKey contextKey = iota

// IdentityFromContext retrieves the VerifiedIdentity injected by Middleware.
func IdentityFromContext(ctx context.Context) (*VerifiedIdentity, bool) {
	v, ok := ctx.Value(identityKey).(*VerifiedIdentity)
	return v, ok && v != nil
}

// MiddlewareMetrics is an optional hook for recording tool-call metrics.
// Implementations should be goroutine-safe (Prometheus counters are).
type MiddlewareMetrics struct {
	// RecordCall is called after each verification attempt with the winning
	// protocol name and "allowed" or "denied".
	RecordCall func(protocol, decision string)
	// ObserveDuration is called with the verification duration in seconds and
	// the winning protocol name.
	ObserveDuration func(protocol string, seconds float64)
	// IncTie is called when two adapters return identical confidence (anomaly).
	IncTie func()
}

// MiddlewareConfig configures the universal tool-call middleware.
type MiddlewareConfig struct {
	// Adapters is the ordered list of protocol adapters to try. Order is the
	// tiebreaker when two adapters return the same confidence level.
	Adapters []Adapter
	// Verifier performs JWT verification and policy enforcement.
	Verifier Verifier
	// MinConfidence is the minimum confidence required to attempt verification.
	// Requests below this threshold are passed through to the next handler.
	// Defaults to MatchPossible if zero.
	MinConfidence MatchConfidence
	// PassThrough, when true, lets requests with no matching adapter reach the
	// next handler instead of returning 401. Useful when the middleware is
	// applied broadly and non-tool-call paths share the same mux.
	PassThrough bool
	// Metrics is an optional hook for Prometheus instrumentation.
	Metrics *MiddlewareMetrics
}

// adapterMatch bundles a match result with its adapter for error formatting.
type adapterMatch struct {
	adapter    Adapter
	result     *MatchResult
	adapterIdx int
}

// Middleware returns an http.Handler that enforces universal tool-call identity
// verification before delegating to next.
func Middleware(cfg MiddlewareConfig, next http.Handler) http.Handler {
	minConf := cfg.MinConfidence
	if minConf == 0 {
		minConf = MatchPossible
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		best, hasTie := selectAdapter(r, cfg.Adapters)

		if hasTie && cfg.Metrics != nil && cfg.Metrics.IncTie != nil {
			cfg.Metrics.IncTie()
			slog.Warn("toolcall: protocol detection tie — two adapters matched at equal confidence",
				"path", r.URL.Path)
		}

		if best == nil || best.result.Confidence < minConf {
			if cfg.PassThrough {
				next.ServeHTTP(w, r)
				return
			}
			// No adapter matched above threshold — pick the first adapter for
			// error formatting, or fall back to plain HTTP.
			if len(cfg.Adapters) > 0 {
				cfg.Adapters[0].FormatError(w, "unauthorized", "no recognized tool-call protocol", http.StatusUnauthorized)
			} else {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			}
			return
		}

		proto := string(best.adapter.Protocol())

		identity, err := cfg.Verifier.Verify(r.Context(), best.result.Request)
		elapsed := time.Since(start).Seconds()

		if cfg.Metrics != nil {
			if cfg.Metrics.ObserveDuration != nil {
				cfg.Metrics.ObserveDuration(proto, elapsed)
			}
		}

		if err != nil {
			if cfg.Metrics != nil && cfg.Metrics.RecordCall != nil {
				cfg.Metrics.RecordCall(proto, "denied")
			}
			code, description, status := classifyVerifyError(err)
			best.adapter.FormatError(w, code, description, status)
			return
		}

		if cfg.Metrics != nil && cfg.Metrics.RecordCall != nil {
			cfg.Metrics.RecordCall(proto, "allowed")
		}

		ctx := context.WithValue(r.Context(), identityKey, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// selectAdapter runs all adapters against the request and returns the best match
// and whether two adapters tied at the top confidence level.
// Highest confidence wins; ties are broken by adapter index (lower = higher priority).
func selectAdapter(r *http.Request, adapters []Adapter) (best *adapterMatch, hasTie bool) {
	type candidate struct {
		adapter    Adapter
		result     *MatchResult
		adapterIdx int
	}

	candidates := make([]candidate, 0, len(adapters))
	for i, a := range adapters {
		res, err := a.ExtractFromHTTP(r)
		if err != nil || res == nil {
			continue
		}
		candidates = append(candidates, candidate{adapter: a, result: res, adapterIdx: i})
	}

	if len(candidates) == 0 {
		return nil, false
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].result.Confidence != candidates[j].result.Confidence {
			return candidates[i].result.Confidence > candidates[j].result.Confidence
		}
		return candidates[i].adapterIdx < candidates[j].adapterIdx
	})

	top := candidates[0]
	tie := len(candidates) > 1 && candidates[1].result.Confidence == top.result.Confidence

	return &adapterMatch{
		adapter:    top.adapter,
		result:     top.result,
		adapterIdx: top.adapterIdx,
	}, tie
}

// classifyVerifyError maps verifier sentinel errors to wire-level error codes.
// Uses errors.Is so wrapped errors (fmt.Errorf("%w: ...", ErrXxx)) are matched correctly.
func classifyVerifyError(err error) (code, description string, status int) {
	switch {
	case errors.Is(err, ErrMissingToken):
		return "missing_token", "authorization token required", http.StatusUnauthorized
	case errors.Is(err, ErrInvalidToken):
		return "invalid_token", "token signature or format invalid", http.StatusUnauthorized
	case errors.Is(err, ErrTokenRevoked):
		return "token_revoked", "credential has been revoked", http.StatusUnauthorized
	case errors.Is(err, ErrToolNotRegistered):
		return "tool_not_found", "tool is not registered", http.StatusNotFound
	case errors.Is(err, ErrCapabilityDenied):
		return "insufficient_capabilities", "token lacks required capabilities", http.StatusForbidden
	case errors.Is(err, ErrBlastRadiusExceeded):
		return "blast_radius_exceeded", "operation exceeds authorized blast radius", http.StatusForbidden
	case errors.Is(err, ErrAudienceMismatch):
		return "audience_mismatch", "token audience does not match tool resource", http.StatusForbidden
	case errors.Is(err, ErrPolicyDenied):
		return "policy_denied", "request denied by policy", http.StatusForbidden
	case errors.Is(err, ErrProtocolDenied):
		return "protocol_denied", "tool does not accept this protocol", http.StatusForbidden
	case errors.Is(err, ErrExecBindingRequired), errors.Is(err, ErrExecPayloadMissing),
		errors.Is(err, ErrExecPayloadMismatch), errors.Is(err, ErrExecOpMismatch),
		errors.Is(err, ErrExecTargetMismatch):
		return "exec_binding_invalid", err.Error(), http.StatusForbidden
	default:
		return "internal_error", "verification failed", http.StatusInternalServerError
	}
}
