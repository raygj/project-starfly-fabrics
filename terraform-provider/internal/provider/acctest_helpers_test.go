package provider

import (
	"encoding/json"
	"testing"
)

// devSubjectJWT is accepted by Starfly dev-mode identity (signature not verified).
const devSubjectJWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZjphY2MifQ."

func acctestBearerToken(t *testing.T) string {
	t.Helper()

	api := newAPIClient(acctestStarflyEndpoint(), acctestHTTP, "")
	body := map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      devSubjectJWT,
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"audience":           "https://api.example.com",
	}
	_, respBody, err := api.request(t.Context(), "POST", "/v1/exchange/token", body)
	if err != nil {
		t.Fatalf("exchange token: %v", err)
	}

	var resp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("decode exchange response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatalf("exchange failed: %s", string(respBody))
	}
	return resp.AccessToken
}

func skipUnlessBearerAuthWorks(t *testing.T) string {
	t.Helper()
	skipUnlessStarflyAPI(t)
	return acctestBearerToken(t)
}
