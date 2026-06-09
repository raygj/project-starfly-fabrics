package mcp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ECT represents an Execution Context Token per draft-nennemann-wimse-ect-00.
// Generated post-execution by the MCP middleware to record what happened.
type ECT struct {
	// Standard JWT claims
	Issuer   string    `json:"iss"`
	Audience []string  `json:"aud"`
	JTI      string    `json:"jti"`
	IssuedAt time.Time `json:"iat"`
	Expires  time.Time `json:"exp"`

	// ECT execution context claims
	ExecAct    string `json:"exec_act,omitempty"`
	InputHash  string `json:"inp_hash,omitempty"`
	OutputHash string `json:"out_hash,omitempty"`
	Target     string `json:"target,omitempty"`
	WorkflowID string `json:"wid,omitempty"`

	// DAG linkage
	ParentIDs []string `json:"par"`

	// Extensions (Starfly-specific metadata)
	Extensions map[string]interface{} `json:"ext,omitempty"`

	// SignedToken is the JWS compact serialization after signing.
	SignedToken string `json:"-"`
}

// ECTRequest carries the data needed to generate an ECT after tool execution.
type ECTRequest struct {
	// Claims from the verified inbound token.
	Claims *VerifiedClaims

	// ToolID is the tool that executed.
	ToolID string

	// ResponseBody is the raw response bytes for out_hash computation.
	ResponseBody []byte

	// DurationMS is how long the tool handler took to execute.
	DurationMS int64

	// ParentIDs are JTIs of parent ECTs (DAG linkage, populated later by ETV-004).
	ParentIDs []string
}

// DefaultECTExpiry is the ECT validity window (5 minutes per spec recommendation).
const DefaultECTExpiry = 5 * time.Minute

// GenerateECT creates a signed Execution Context Token recording a completed tool call.
// Returns the ECT struct with SignedToken populated, or an error.
func GenerateECT(req *ECTRequest, issuer string, signingKey crypto.Signer, kid string) (*ECT, error) {
	now := time.Now().UTC()
	jti := uuid.New().String()

	ect := &ECT{
		Issuer:   issuer,
		JTI:      jti,
		IssuedAt: now,
		Expires:  now.Add(DefaultECTExpiry),
		ParentIDs: req.ParentIDs,
	}
	if ect.ParentIDs == nil {
		ect.ParentIDs = []string{}
	}

	// Audience: the agent that called + audit ledger.
	ect.Audience = []string{req.Claims.Subject}
	if issuer != "" {
		ect.Audience = append(ect.Audience, issuer+"/audit-ledger")
	}

	// ECT execution claims from the verified inbound token.
	if req.Claims.Execution != nil {
		ex := req.Claims.Execution
		ect.ExecAct = ex.ExecAct
		ect.InputHash = ex.InputHash
		ect.Target = ex.Target
		ect.WorkflowID = ex.WorkflowID
	}

	// out_hash — SHA-256 of the response body.
	if len(req.ResponseBody) > 0 {
		h := sha256.Sum256(req.ResponseBody)
		ect.OutputHash = base64.RawURLEncoding.EncodeToString(h[:])
	}

	// Starfly-specific extensions.
	ect.Extensions = map[string]interface{}{
		"starfly.tool_id":     req.ToolID,
		"starfly.duration_ms": req.DurationMS,
	}

	// Build the JWT.
	token := jwt.New()
	claims := map[string]interface{}{
		"iss":      ect.Issuer,
		"aud":      ect.Audience,
		"jti":      ect.JTI,
		"iat":      ect.IssuedAt.Unix(),
		"exp":      ect.Expires.Unix(),
		"exec_act": ect.ExecAct,
		"par":      ect.ParentIDs,
		"ext":      ect.Extensions,
	}
	if ect.InputHash != "" {
		claims["inp_hash"] = ect.InputHash
	}
	if ect.OutputHash != "" {
		claims["out_hash"] = ect.OutputHash
	}
	if ect.Target != "" {
		claims["target"] = ect.Target
	}
	if ect.WorkflowID != "" {
		claims["wid"] = ect.WorkflowID
	}

	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			return nil, fmt.Errorf("setting ECT claim %q: %w", k, err)
		}
	}

	// Set the JOSE header typ to "wimse-exec+jwt".
	hdrs := jws.NewHeaders()
	if err := hdrs.Set("typ", "wimse-exec+jwt"); err != nil {
		return nil, fmt.Errorf("setting ECT typ header: %w", err)
	}
	if kid != "" {
		if err := hdrs.Set("kid", kid); err != nil {
			return nil, fmt.Errorf("setting ECT kid header: %w", err)
		}
	}

	// Sign.
	alg := inferSignerAlgorithm(signingKey)
	signed, err := jwt.Sign(token,
		jwt.WithKey(alg, signingKey, jws.WithProtectedHeaders(hdrs)),
	)
	if err != nil {
		return nil, fmt.Errorf("signing ECT: %w", err)
	}
	ect.SignedToken = string(signed)

	return ect, nil
}

// inferSignerAlgorithm picks the JWA algorithm based on the crypto.Signer's public key type.
func inferSignerAlgorithm(key crypto.Signer) jwa.SignatureAlgorithm {
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		return jwa.ES256()
	case ed25519.PublicKey:
		return jwa.EdDSA()
	case *rsa.PublicKey:
		return jwa.RS256()
	default:
		return jwa.RS256()
	}
}

// responseCapture wraps http.ResponseWriter to capture the response body and status code.
type responseCapture struct {
	http.ResponseWriter
	body       []byte
	statusCode int
}

func newResponseCapture(w http.ResponseWriter) *responseCapture {
	return &responseCapture{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	rc.body = append(rc.body, b...)
	return rc.ResponseWriter.Write(b)
}
