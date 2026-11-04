package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetryAfterReachesHostErrorEnvelope(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 500000000, time.UTC)
	for _, tc := range []struct {
		name, value string
		seconds     int
	}{
		{"seconds", "15", 15},
		{"http-date", now.Add(3 * time.Second).Format(http.TimeFormat), 3},
		{"invalid", "invalid", 0},
		{"past", now.Add(-time.Minute).Format(http.TimeFormat), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delay := parseRetryAfter(map[string][]string{"retry-after": {tc.value}}, now)
			err := fmt.Errorf("upstream: %w", httpStatusError{status: 429, message: "rate limited", retryAfterSeconds: delay})
			var response envelope
			if err := json.Unmarshal(envelopeForError(err), &response); err != nil {
				t.Fatal(err)
			}
			if response.OK || response.Error == nil || response.Error.HTTPStatus != 429 || response.Error.RetryAfterSeconds != tc.seconds {
				t.Fatalf("host error = %+v, want HTTP 429 and Retry-After %d", response.Error, tc.seconds)
			}
		})
	}
}

func decodeResult(t *testing.T, raw []byte, target any) {
	t.Helper()
	var response envelope
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatalf("plugin response failed: %s", raw)
	}
	if err := json.Unmarshal(response.Result, target); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationAndModelCatalog(t *testing.T) {
	var registration map[string]any
	raw, err := handleMethod("plugin.register", nil)
	if err != nil {
		t.Fatal(err)
	}
	decodeResult(t, raw, &registration)
	if registration["schema_version"] != float64(schemaVersion) {
		t.Fatalf("schema version = %#v", registration["schema_version"])
	}
	var modelsResp modelResponse
	raw, err = handleMethod("model.register", nil)
	if err != nil {
		t.Fatal(err)
	}
	decodeResult(t, raw, &modelsResp)
	if modelsResp.Provider != provider || len(modelsResp.Models) != 3 {
		t.Fatalf("catalog = %#v", modelsResp)
	}
	for _, model := range modelsResp.Models {
		if !strings.HasPrefix(model.ID, provider+"/") || model.OwnedBy != provider {
			t.Fatalf("model identity = %#v, want %s namespace", model, provider)
		}
	}
}

func TestEnsureModelStripsProviderNamespace(t *testing.T) {
	body, err := ensureModel([]byte(`{"messages":[{"role":"user","content":"hi"}],"store":false}`), provider+"/zai-glm-5-3", false)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["model"] != "zai-glm-5-3" || payload["stream"] != false {
		t.Fatalf("payload = %#v", payload)
	}
	if _, exists := payload["store"]; exists {
		t.Fatal("Mistral rejects OpenAI's store parameter")
	}
}

func TestHostHTTPResponseUsesSDKFieldNames(t *testing.T) {
	var response hostHTTPResponse
	if err := json.Unmarshal([]byte(`{"StatusCode":200,"Headers":{"Content-Type":["application/json"]},"Body":"e30="}`), &response); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || string(response.Body) != "{}" || response.Headers["Content-Type"][0] != "application/json" {
		t.Fatalf("host HTTP response = %#v", response)
	}
}

func TestAssistantReasoningRoundTripsForToolCalls(t *testing.T) {
	body, err := ensureModel([]byte(`{"messages":[{"role":"assistant","content":"","reasoning_content":"Read the file","tool_calls":[{"id":"tool1"}]},{"role":"tool","content":"result","tool_call_id":"tool1"}]}`), provider+"/zai-glm-5-3", true)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct{ Messages []map[string]any }
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	assistant := payload.Messages[0]
	if _, exists := assistant["reasoning_content"]; exists {
		t.Fatal("Mistral rejects reasoning_content on assistant messages")
	}
	blocks := assistant["content"].([]any)
	if len(blocks) != 1 || blocks[0].(map[string]any)["type"] != "thinking" || len(assistant["tool_calls"].([]any)) != 1 || payload.Messages[1]["tool_call_id"] != "tool1" {
		t.Fatalf("payload = %s", body)
	}
}

func TestMistralContentBlocksBecomeOpenAIStrings(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"role":"assistant","content":[{"type":"thinking","thinking":[{"type":"text","text":"reason"}],"closed":true},{"type":"text","text":"O"},{"type":"text","text":"K"}],"tool_calls":[{"id":"call1"}]}}],"usage":{"total_tokens":8}}`)
	var response struct {
		Choices []struct {
			Message struct {
				Content   string
				Reasoning string `json:"reasoning_content"`
				ToolCalls []any  `json:"tool_calls"`
			}
		}
		Usage map[string]any
	}
	if err := json.Unmarshal(normalizeCompletion(body), &response); err != nil {
		t.Fatal(err)
	}
	message := response.Choices[0].Message
	if message.Content != "OK" || message.Reasoning != "reason" || len(message.ToolCalls) != 1 || response.Usage["total_tokens"] != float64(8) {
		t.Fatalf("normalized = %#v", response)
	}
}

func TestSSEContentBlocksAcrossTransportChunks(t *testing.T) {
	input := "data: " + `{"choices":[{"delta":{"content":[{"type":"text","text":"OK"}]}}]}` + "\n\ndata: [DONE]\n\n"
	var normalizer sseNormalizer
	var output []byte
	for _, b := range []byte(input) {
		output = append(output, normalizer.write([]byte{b})...)
	}
	if len(normalizer.pending) != 0 || !strings.Contains(string(output), `"content":"OK"`) || !strings.HasSuffix(string(output), "data: [DONE]\n\n") {
		t.Fatalf("SSE = %s", output)
	}
	plain := []byte(`{"choices":[{"message":{"content":"OK"}}]}`)
	if string(normalizeCompletion(plain)) != string(plain) {
		t.Fatal("plain OpenAI responses must be preserved")
	}
}

func TestMistralIsExcludedOnlyFromCodexCatalog(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		modified   bool
	}{
		{"codex", `{"models":[{"slug":"gpt-6.1-sol"},{"slug":"mistral-vibe/zai-glm-5-3"}],"metadata":{"version":1}}`, true},
		{"openai", `{"data":[{"id":"mistral-vibe/zai-glm-5-3","owned_by":"mistral-vibe"}]}`, false},
		{"completion", `{"choices":[{"message":{"content":"hello"}}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := handleMethod("response.intercept_after", mustJSON(struct{ Body []byte }{[]byte(tc.body)}))
			if err != nil {
				t.Fatal(err)
			}
			var response struct{ Body []byte }
			decodeResult(t, raw, &response)
			if (len(response.Body) > 0) != tc.modified {
				t.Fatalf("response = %s", response.Body)
			}
			if tc.modified {
				var catalog struct {
					Models   []struct{ Slug string }
					Metadata map[string]any
				}
				if err := json.Unmarshal(response.Body, &catalog); err != nil {
					t.Fatal(err)
				}
				if len(catalog.Models) != 1 || catalog.Models[0].Slug != "gpt-6.1-sol" || catalog.Metadata["version"] != float64(1) {
					t.Fatalf("catalog = %#v", catalog)
				}
			}
		})
	}
}

func TestStartLoginUsesPKCEAndFixedMistralRedirect(t *testing.T) {
	raw, err := handleMethod("auth.login.start", mustJSON(authStartRequest{Provider: provider, Host: hostSummary{AuthDir: t.TempDir()}}))
	if err != nil {
		t.Fatal(err)
	}
	var response authStartResponse
	decodeResult(t, raw, &response)
	u, err := url.Parse(response.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("redirect_uri") != redirectURI || u.Query().Get("state") != response.State {
		t.Fatalf("OAuth URL = %s", response.URL)
	}
	if u.Query().Get("code_challenge") == "" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("OAuth URL does not contain PKCE: %s", response.URL)
	}
	flowMu.Lock()
	_, ok := flows[response.State]
	flowMu.Unlock()
	if !ok {
		t.Fatal("login flow was not retained")
	}
}

func TestParseAuthRecognizesMistralStorage(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).Unix()
	storage, _ := json.Marshal(storedAuth{Type: provider, IDToken: "id-token", RefreshToken: "refresh-token", OrgID: "org", WorkspaceID: "workspace", ExpiresAt: expiresAt})
	raw, err := handleMethod("auth.parse", mustJSON(authRequest{FileName: "mistral.json", RawJSON: storage}))
	if err != nil {
		t.Fatal(err)
	}
	var response authParseResponse
	decodeResult(t, raw, &response)
	if !response.Handled || response.Auth.Provider != provider || string(response.Auth.StorageJSON) == "" {
		t.Fatalf("parsed auth = %#v", response)
	}
	if !response.Auth.NextRefreshAfter.Equal(time.Unix(expiresAt-60, 0)) || response.Auth.Metadata["expires_at"] != float64(expiresAt) || response.Auth.Metadata["refresh_interval_seconds"] != float64(60) {
		t.Fatalf("refresh schedule = %#v", response.Auth)
	}
}

func TestReadCallbackAcceptsMistralAlias(t *testing.T) {
	dir := t.TempDir()
	state := "test-state"
	path := filepath.Join(dir, ".oauth-mistral-"+state+".oauth")
	if err := os.WriteFile(path, []byte(`{"state":"test-state","code":"code"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	gotPath, raw, err := readCallback(dir, "mistral", state)
	if err != nil || gotPath != path || !strings.Contains(string(raw), "code") {
		t.Fatalf("callback = %q %q %v", gotPath, raw, err)
	}
}

func TestVerifyIDTokenClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, _ := json.Marshal(map[string]any{"iss": "https://auth.mistral.ai", "aud": []string{clientID}, "exp": float64(4102444800)})
	token := header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
	if _, err := verifyIDToken(token); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}
