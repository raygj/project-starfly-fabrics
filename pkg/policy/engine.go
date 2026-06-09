// Package policy provides OPA-based policy evaluation for Starfly.
//
// The Engine loads Rego policy files from a bundle directory, compiles them,
// and evaluates policy decisions for token exchange, signal processing, and
// identity operations. Each action maps to a Rego package under the
// "starfly" namespace (e.g., data.starfly.exchange).
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const tracerName = "github.com/starfly-fabrics/starfly/pkg/policy"

// Engine implements core.PolicyEngine using the Open Policy Agent.
type Engine struct {
	compiler *ast.Compiler
	store    storage.Store
	mu       sync.RWMutex
	auditor  core.Auditor
	policyCfg core.PolicyConfig
}

// Compile-time interface check.
var _ core.PolicyEngine = (*Engine)(nil)

// New creates a new policy engine. The auditor is used to emit audit events
// when bundle verification fails (may be nil to disable audit logging).
// Call LoadBundle to load policies before evaluating any decisions.
func New(auditor core.Auditor, policyCfg core.PolicyConfig) *Engine {
	return &Engine{
		auditor:   auditor,
		policyCfg: policyCfg,
	}
}

// LoadBundle walks the directory at bundlePath, parses all .rego files, and
// compiles them into a single OPA compiler. It also loads any data.json files
// found in the bundle directory into an in-memory store for use as external
// data in policy evaluation. The compiled result replaces any previously
// loaded policies atomically under a write lock.
func (e *Engine) LoadBundle(ctx context.Context, bundlePath string) error {
	info, err := os.Stat(bundlePath)
	if err != nil {
		return fmt.Errorf("accessing bundle path %q: %w", bundlePath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("bundle path %q is not a directory", bundlePath)
	}

	// Verify bundle signature when signing key is configured.
	if err := VerifyBundle(bundlePath, e.policyCfg); err != nil {
		if e.auditor != nil {
			_ = e.auditor.Log(ctx, &core.AuditEvent{
				Type:     "policy",
				Action:   "bundle_rejected",
				Target:   bundlePath,
				Decision: "denied",
				Reason:   err.Error(),
			})
		}
		return fmt.Errorf("bundle verification failed: %w", err)
	}

	modules := make(map[string]*ast.Module)
	storeData := make(map[string]interface{})

	err = filepath.Walk(bundlePath, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fi.IsDir() {
			// Skip Kubernetes ConfigMap atomic symlink directories (e.g., "..2026_03_28_01_58_34.123456789").
			if strings.HasPrefix(fi.Name(), "..") {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, _ := filepath.Rel(bundlePath, path)

		switch {
		case strings.HasSuffix(fi.Name(), ".rego"):
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return fmt.Errorf("reading %q: %w", path, readErr)
			}

			mod, parseErr := ast.ParseModule(relPath, string(data))
			if parseErr != nil {
				return fmt.Errorf("parsing %q: %w", relPath, parseErr)
			}

			modules[relPath] = mod

		case fi.Name() == "data.json":
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return fmt.Errorf("reading %q: %w", path, readErr)
			}

			var doc map[string]interface{}
			if jsonErr := json.Unmarshal(raw, &doc); jsonErr != nil {
				return fmt.Errorf("parsing %q: %w", relPath, jsonErr)
			}

			// Merge data document keys into the store data.
			for k, v := range doc {
				storeData[k] = v
			}
			slog.Info("data file loaded", "file", relPath)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("walking bundle directory: %w", err)
	}

	if len(modules) == 0 {
		return fmt.Errorf("no .rego files found in %q", bundlePath)
	}

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		return fmt.Errorf("compiling policies: %v", compiler.Errors)
	}

	store := inmem.NewFromObject(storeData)

	e.mu.Lock()
	e.compiler = compiler
	e.store = store
	e.mu.Unlock()

	for name := range modules {
		slog.Info("policy loaded", "file", name)
	}
	slog.Info("policy bundle compiled", "files", len(modules))

	return nil
}

// Evaluate runs the policy for the given action and returns a decision.
// The engine queries data.starfly.<action>.allow, data.starfly.<action>.reason,
// and data.starfly.<action>.claims. If the action's package does not exist or
// returns no results, the default decision is deny with reason "no policy found".
func (e *Engine) Evaluate(ctx context.Context, input *core.PolicyInput) (*core.PolicyDecision, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "policy.Evaluate")
	defer span.End()

	span.SetAttributes(attribute.String("action", input.Action))

	e.mu.RLock()
	compiler := e.compiler
	store := e.store
	e.mu.RUnlock()

	if compiler == nil {
		span.SetAttributes(attribute.Bool("decision", false))
		return &core.PolicyDecision{
			Allowed: false,
			Reason:  "no policy found",
		}, nil
	}

	decision := &core.PolicyDecision{
		Allowed: false,
		Reason:  "no policy found",
	}

	// Query the allow rule.
	allowQuery := fmt.Sprintf("data.starfly.%s.allow", input.Action)
	allowed, err := e.evalRule(ctx, compiler, store, allowQuery, input)
	if err != nil {
		telemetry.SpanError(span, err)
		return nil, fmt.Errorf("evaluating allow rule: %w", err)
	}
	if b, ok := allowed.(bool); ok {
		decision.Allowed = b
		decision.Reason = "" // clear default reason if we got a result
	}

	// Query the reason rule.
	reasonQuery := fmt.Sprintf("data.starfly.%s.reason", input.Action)
	reasonVal, err := e.evalRule(ctx, compiler, store, reasonQuery, input)
	if err != nil {
		telemetry.SpanError(span, err)
		return nil, fmt.Errorf("evaluating reason rule: %w", err)
	}
	if s, ok := reasonVal.(string); ok {
		decision.Reason = s
	}

	// Query the claims rule.
	claimsQuery := fmt.Sprintf("data.starfly.%s.claims", input.Action)
	claimsVal, err := e.evalRule(ctx, compiler, store, claimsQuery, input)
	if err != nil {
		telemetry.SpanError(span, err)
		return nil, fmt.Errorf("evaluating claims rule: %w", err)
	}
	if m, ok := claimsVal.(map[string]interface{}); ok {
		decision.Claims = m
	}

	span.SetAttributes(attribute.Bool("decision", decision.Allowed))
	return decision, nil
}

// evalRule evaluates a single Rego query and returns the result value, or nil
// if the query produced no results.
func (e *Engine) evalRule(ctx context.Context, compiler *ast.Compiler, store storage.Store, query string, input *core.PolicyInput) (interface{}, error) {
	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Compiler(compiler),
		rego.Input(toMap(input)),
	}
	if store != nil {
		opts = append(opts, rego.Store(store))
	}

	r := rego.New(opts...)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, err
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}

	return rs[0].Expressions[0].Value, nil
}

// toMap converts a PolicyInput to a map for use as OPA input.
func toMap(input *core.PolicyInput) map[string]interface{} {
	m := map[string]interface{}{
		"action": input.Action,
		"target": input.Target,
	}

	if input.Subject != nil {
		subj := map[string]interface{}{
			"id":           input.Subject.ID,
			"trust_domain": input.Subject.TrustDomain,
			"claims":       input.Subject.Claims,
		}
		if input.Subject.Attestation != nil {
			subj["attestation"] = map[string]interface{}{
				"method":    input.Subject.Attestation.Method,
				"timestamp": input.Subject.Attestation.Timestamp,
				"node_id":   input.Subject.Attestation.NodeID,
				"namespace": input.Subject.Attestation.Namespace,
			}
		}
		m["subject"] = subj
	}

	if input.Context != nil {
		m["context"] = input.Context
	}

	return m
}
