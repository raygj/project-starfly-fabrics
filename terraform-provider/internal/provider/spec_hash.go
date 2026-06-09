package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	starflyv1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

func hashStarlightFabricSpec(spec starflyv1.StarlightFabricSpec) (string, error) {
	canonical, err := canonicalJSON(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	normalized := sortJSON(decoded)
	return json.Marshal(normalized)
}

func sortJSON(v any) any {
	switch value := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for k := range value {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(keys))
		for _, k := range keys {
			out[k] = sortJSON(value[k])
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = sortJSON(item)
		}
		return out
	default:
		return v
	}
}

// HashSpec is exported for tests.
func HashSpec(ctx context.Context, spec starflyv1.StarlightFabricSpec) (string, error) {
	_ = ctx
	return hashStarlightFabricSpec(spec)
}
