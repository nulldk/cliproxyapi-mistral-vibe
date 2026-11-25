package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVibeCredentialRouting(t *testing.T) {
	stored := storedAuth{APIKey: "vibe-key", IDToken: "oauth-id", AccessToken: "oauth-access", OrgID: "oauth-org", WorkspaceID: "oauth-workspace"}
	headers := authHeaders(stored, map[string][]string{
		"authorization": {"Bearer client-key"}, "user-agent": {"Google"},
		"X-External-Organization-Id": {"client-org"}, "X-External-Workspace-Id": {"client-workspace"},
	})
	if got := headers["Authorization"]; len(got) != 1 || got[0] != "Bearer vibe-key" {
		t.Fatalf("inference must use the Vibe key: %v", got)
	}
	for name := range headers {
		if strings.HasPrefix(strings.ToLower(name), "x-external-") || name == "authorization" || strings.EqualFold(name, "user-agent") {
			t.Fatalf("caller/OAuth routing header leaked into Vibe request: %s", name)
		}
	}
	keyOnly := []byte(`{"type":"mistral-vibe","api_key":"vibe-key"}`)
	if _, err := credentials(keyOnly); err != nil {
		t.Fatal(err)
	}
	parsed, err := parseAuth(authRequest{RawJSON: keyOnly, FileName: "vibe.json"})
	if err != nil || !strings.Contains(string(parsed), `"Handled":true`) {
		t.Fatalf("key-only credential was not parsed: %s, %v", parsed, err)
	}
	stored.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	stored.CatalogNextCheck = time.Now().Add(catalogInterval).Unix()
	if nextRefresh(stored).Unix() != stored.CatalogNextCheck || authMetadata(stored)["expires_at"] != nil {
		t.Fatal("Vibe key must not expire or refresh with an unused OAuth token")
	}
	request := executorRequest{StorageJSON: []byte(`{"id_token":"oauth-id"}`)}
	for _, execute := range []func(executorRequest) ([]byte, error){execute, executeStream} {
		if _, err := execute(request); err == nil || !strings.Contains(err.Error(), "Vibe-scoped api_key") {
			t.Fatalf("OAuth-only inference must fail before consuming API budget: %v", err)
		}
	}
}

func TestInferenceAttributionMetadata(t *testing.T) {
	// No metadata: both attribution fields are injected.
	body, err := ensureModel([]byte(`{"model":"zai-glm-5-3","messages":[{"role":"user","content":"hi"}]}`), "zai-glm-5-3", false)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Metadata["call_source"] != "vibe_code" || payload.Metadata["call_type"] != "main_call" {
		t.Fatalf("missing Vibe call source in inference metadata: %v", payload.Metadata)
	}

	// Partial metadata: unknown fields survive, call_source is forced, a
	// caller-supplied call_type is preserved.
	body, err = ensureModel([]byte(`{"model":"zai-glm-5-3","metadata":{"session_id":"abc123","call_source":"other-client"}}`), "zai-glm-5-3", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Metadata["call_source"] != "vibe_code" || payload.Metadata["call_type"] != "main_call" || payload.Metadata["session_id"] != "abc123" {
		t.Fatalf("Vibe metadata merge lost caller fields: %v", payload.Metadata)
	}

	body, err = ensureModel([]byte(`{"model":"zai-glm-5-3","metadata":{"call_type":"secondary_call","user_plan":"PRO"}}`), "zai-glm-5-3", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Metadata["call_source"] != "vibe_code" || payload.Metadata["call_type"] != "secondary_call" || payload.Metadata["user_plan"] != "PRO" {
		t.Fatalf("Vibe metadata merge overrode the caller call_type: %v", payload.Metadata)
	}

	// Non-map metadata is replaced, never serialized as a broken field.
	body, err = ensureModel([]byte(`{"model":"zai-glm-5-3","metadata":"not-an-object"}`), "zai-glm-5-3", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Metadata["call_source"] != "vibe_code" || payload.Metadata["call_type"] != "main_call" {
		t.Fatalf("non-map metadata was not replaced: %v", payload.Metadata)
	}
}

func TestQuotaBudgetMapping(t *testing.T) {
	// Both budgets from GET /v1/billing/budget (live response shape).
	raw := `{"vibe_budget":{"usage_percentage":11.03,"initial_budget":255.0,"currency":"EUR","reset_at":"2026-12-01T00:00:00Z","payg_enabled":false},"api_budget":{"usage_percentage":0.000049,"initial_budget":25.5,"currency":"EUR","reset_at":"2026-12-01T00:00:00Z"}}`
	quota, err := budgetQuotaResponse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(quota.Summary) != 4 {
		t.Fatalf("expected one initial and one remaining metric per budget: %v", quota.Summary)
	}
	if quota.Summary[0].Key != "vibe_initial" || quota.Summary[0].Value != 255 || quota.Summary[0].Format != "currency" || quota.Summary[0].Currency != "EUR" {
		t.Fatalf("vibe initial metric wrong: %v", quota.Summary[0])
	}
	if len(quota.Groups) != 1 || len(quota.Groups[0].Buckets) != 2 {
		t.Fatalf("expected both budgets as quota buckets: %v", quota.Groups)
	}
	vibe := quota.Groups[0].Buckets[0]
	api := quota.Groups[0].Buckets[1]
	if vibe.Window != "monthly" || vibe.ResetTime != "2026-12-01T00:00:00Z" {
		t.Fatalf("vibe bucket window missing: %v", vibe)
	}
	if diff := vibe.RemainingFraction - 0.8897; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("vibe remaining fraction wrong: %v", vibe.RemainingFraction)
	}
	if diff := api.RemainingFraction - 0.99999951; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("api remaining fraction wrong: %v", api.RemainingFraction)
	}

	// Overshoot is clamped to an empty bucket.
	quota, err = budgetQuotaResponse([]byte(`{"vibe_budget":{"usage_percentage":140,"initial_budget":255,"currency":"EUR"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if quota.Groups[0].Buckets[0].RemainingFraction != 0 {
		t.Fatalf("over-consumption must clamp to zero remaining: %v", quota.Groups[0].Buckets[0])
	}

	// Absent buckets are skipped, empty responses are errors.
	quota, err = budgetQuotaResponse([]byte(`{"vibe_budget":{"usage_percentage":1,"initial_budget":255,"currency":"EUR"}}`))
	if err != nil || len(quota.Groups[0].Buckets) != 1 {
		t.Fatalf("missing api_budget must not fail the whole quota: %v, %v", quota, err)
	}
	if _, err := budgetQuotaResponse([]byte(`{}`)); err == nil {
		t.Fatal("a budget response without budgets must error")
	}
	if _, err := budgetQuotaResponse([]byte(`not-json`)); err == nil {
		t.Fatal("an invalid budget response must error")
	}
}

func TestQuotaCacheTTL(t *testing.T) {
	quotaMu.Lock()
	clear := len(quotaCache)
	quotaCache = map[string]cachedQuota{}
	quotaMu.Unlock()
	defer func() {
		if clear > 0 {
			t.Log("test replaced a non-empty quota cache")
		}
	}()
	now := time.Now()
	response := quotaFetchResponse{Summary: []quotaMetric{{Key: "vibe_initial", Label: "Vibe & Studio allowance", Value: 255, Format: "currency", Currency: "EUR"}}}
	quotaCacheStore("auth.json", response, now)
	if cached, ok := quotaCacheLoad("auth.json", now.Add(quotaCacheTTL-time.Second)); !ok || len(cached.Summary) != 1 {
		t.Fatalf("fresh quota was not served from cache: %v, %v", cached, ok)
	}
	if _, ok := quotaCacheLoad("auth.json", now.Add(quotaCacheTTL)); ok {
		t.Fatal("expired quota must not be served from cache")
	}
	if _, ok := quotaCacheLoad("auth.json", now.Add(quotaCacheTTL)); ok {
		t.Fatal("expired quota must be evicted")
	}
}

func TestStaticModelSurvivesCachedCatalogue(t *testing.T) {
	extra := staticModels()[0]
	for _, models := range [][]modelInfo{{}, {extra}} {
		stored := storedAuth{APIKey: "vibe-key", ModelCatalog: models, CatalogFetchedAt: 1, CatalogNextCheck: time.Now().Add(catalogInterval).Unix()}
		raw, _ := json.Marshal(stored)
		result, err := modelsForAuth(authRefreshRequest{StorageJSON: raw})
		if err != nil {
			t.Fatal(err)
		}
		var response struct{ Result modelResponse }
		if err := json.Unmarshal(result, &response); err != nil {
			t.Fatal(err)
		}
		if len(response.Result.Models) != 1 || response.Result.Models[0].ID != extra.ID {
			t.Fatalf("static model missing or duplicated: %s", result)
		}
	}
}
