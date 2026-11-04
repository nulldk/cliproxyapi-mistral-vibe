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
