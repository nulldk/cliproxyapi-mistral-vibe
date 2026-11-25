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
