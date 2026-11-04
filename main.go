package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct { void *ptr; size_t len; } cliproxy_buffer;
typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);
typedef struct {
  uint32_t abi_version;
  void *host_ctx;
  cliproxy_host_call_fn call;
  cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct {
  uint32_t abi_version;
  cliproxy_plugin_call_fn call;
  cliproxy_plugin_free_fn free_buffer;
  cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api *stored_host;
static void store_host_api(const cliproxy_host_api *host) { stored_host = host; }
static int call_host_api(const char *method, const uint8_t *request, size_t request_len, cliproxy_buffer *response) {
  if (stored_host == NULL || stored_host->call == NULL) return 1;
  return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}
static void free_host_buffer(void *ptr, size_t len) {
  if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL)
    stored_host->free_buffer(ptr, len);
}
*/
import "C"

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const (
	abiVersion      = 1
	schemaVersion   = 10
	provider        = "mistral-vibe"
	clientID        = "829da7e7-628f-4795-829a-8cca609c76d4"
	tokenURL        = "https://auth.mistral.ai/oauth2/token"
	workspaceURL    = "https://api.mistral.ai/v1/users/me/workspaces?limit=100&offset=0"
	apiBaseURL      = "https://api.mistral.ai/v1"
	catalogInterval = 30 * time.Minute
	catalogRetry    = time.Minute
	redirectURI     = "http://127.0.0.1:8766/callback"
)

var (
	flowMu          sync.Mutex
	flows           = map[string]oauthFlow{}
	catalogMu       sync.RWMutex
	catalogMetadata = map[string]modelInfo{}
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *pluginError    `json:"error,omitempty"`
}

type pluginError struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	HTTPStatus        int    `json:"http_status,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

type oauthFlow struct {
	Verifier    string
	RedirectURI string
	CreatedAt   time.Time
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type storedAuth struct {
	Type             string      `json:"type,omitempty"`
	Provider         string      `json:"provider,omitempty"`
	AccessToken      string      `json:"access_token,omitempty"`
	IDToken          string      `json:"id_token,omitempty"`
	RefreshToken     string      `json:"refresh_token,omitempty"`
	ExpiresAt        int64       `json:"expires_at,omitempty"`
	OrgID            string      `json:"org_id,omitempty"`
	WorkspaceID      string      `json:"workspace_id,omitempty"`
	Label            string      `json:"label,omitempty"`
	ModelCatalog     []modelInfo `json:"model_catalog,omitempty"`
	CatalogFetchedAt int64       `json:"model_catalog_fetched_at,omitempty"`
	CatalogNextCheck int64       `json:"model_catalog_next_check,omitempty"`
}

type callbackPayload struct {
	Code  string `json:"code"`
	State string `json:"state"`
	Error string `json:"error"`
}

type authRequest struct {
	Provider string      `json:"Provider"`
	Path     string      `json:"Path"`
	FileName string      `json:"FileName"`
	RawJSON  []byte      `json:"RawJSON"`
	Host     hostSummary `json:"Host"`
}

type hostSummary struct {
	AuthDir string `json:"AuthDir"`
}

type authData struct {
	Provider         string            `json:"Provider"`
	ID               string            `json:"ID"`
	FileName         string            `json:"FileName"`
	Label            string            `json:"Label"`
	StorageJSON      []byte            `json:"StorageJSON"`
	Metadata         map[string]any    `json:"Metadata,omitempty"`
	Attributes       map[string]string `json:"Attributes,omitempty"`
	NextRefreshAfter time.Time         `json:"NextRefreshAfter,omitempty"`
}

type authParseResponse struct {
	Handled bool     `json:"Handled"`
	Auth    authData `json:"Auth"`
}

type authStartRequest struct {
	Provider       string         `json:"Provider"`
	BaseURL        string         `json:"BaseURL"`
	Host           hostSummary    `json:"Host"`
	Metadata       map[string]any `json:"Metadata"`
	HostCallbackID string         `json:"host_callback_id,omitempty"`
}

type authStartResponse struct {
	Provider  string         `json:"Provider"`
	URL       string         `json:"URL"`
	State     string         `json:"State"`
	ExpiresAt time.Time      `json:"ExpiresAt"`
	Metadata  map[string]any `json:"Metadata,omitempty"`
}

type authPollRequest struct {
	Provider       string         `json:"Provider"`
	State          string         `json:"State"`
	Host           hostSummary    `json:"Host"`
	Metadata       map[string]any `json:"Metadata"`
	HostCallbackID string         `json:"host_callback_id,omitempty"`
}

type authPollResponse struct {
	Status  string   `json:"Status"`
	Message string   `json:"Message,omitempty"`
	Auth    authData `json:"Auth"`
}

type authRefreshRequest struct {
	AuthID         string         `json:"AuthID"`
	AuthProvider   string         `json:"AuthProvider"`
	StorageJSON    []byte         `json:"StorageJSON"`
	Metadata       map[string]any `json:"Metadata"`
	Host           hostSummary    `json:"Host"`
	HostCallbackID string         `json:"host_callback_id,omitempty"`
}

type authRefreshResponse struct {
	Auth             authData  `json:"Auth"`
	NextRefreshAfter time.Time `json:"NextRefreshAfter"`
}

type modelInfo struct {
	ID                       string   `json:"ID"`
	Object                   string   `json:"Object"`
	OwnedBy                  string   `json:"OwnedBy"`
	DisplayName              string   `json:"DisplayName"`
	Name                     string   `json:"Name"`
	ContextLength            int64    `json:"ContextLength"`
	MaxCompletionTokens      int64    `json:"MaxCompletionTokens"`
	SupportedInputModalities []string `json:"SupportedInputModalities,omitempty"`
	Recommended              bool     `json:"Recommended,omitempty"`
	Description              string   `json:"Description,omitempty"`
	UserDefined              bool     `json:"UserDefined"`
}

type modelResponse struct {
	Provider   string      `json:"Provider"`
	Models     []modelInfo `json:"Models"`
	AuthUpdate *authData   `json:"AuthUpdate,omitempty"`
}

type executorRequest struct {
	AuthID          string              `json:"AuthID"`
	AuthProvider    string              `json:"AuthProvider"`
	Model           string              `json:"Model"`
	Format          string              `json:"Format"`
	Stream          bool                `json:"Stream"`
	Headers         map[string][]string `json:"Headers"`
	OriginalRequest []byte              `json:"OriginalRequest"`
	Payload         []byte              `json:"Payload"`
	StorageJSON     []byte              `json:"StorageJSON"`
	AuthMetadata    map[string]any      `json:"AuthMetadata"`
	AuthAttributes  map[string]string   `json:"AuthAttributes"`
	HostCallbackID  string              `json:"host_callback_id,omitempty"`
	StreamID        string              `json:"stream_id,omitempty"`
}

type executorResponse struct {
	Payload  []byte              `json:"Payload"`
	Headers  map[string][]string `json:"Headers,omitempty"`
	Metadata map[string]any      `json:"Metadata,omitempty"`
}

type executorStreamResponse struct {
	Headers map[string][]string `json:"Headers,omitempty"`
	Chunks  []streamChunk       `json:"Chunks,omitempty"`
}

type streamChunk struct {
	Payload []byte `json:"Payload,omitempty"`
	Error   string `json:"Error,omitempty"`
}

type hostHTTPResponse struct {
	// The non-streaming bridge uses SDK field names, unlike its streaming RPC.
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

type hostHTTPStreamResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers,omitempty"`
	StreamID   string              `json:"stream_id"`
}

type hostHTTPStreamReadResponse struct {
	Payload []byte `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
	Done    bool   `json:"done,omitempty"`
}

type hostHTTPStreamReadRequest struct {
	StreamID string `json:"stream_id"`
}
type hostHTTPStreamCloseRequest struct {
	StreamID string `json:"stream_id"`
}
type hostStreamEmitRequest struct {
	StreamID string `json:"stream_id"`
	Payload  []byte `json:"payload,omitempty"`
	Error    string `json:"error,omitempty"`
}
type hostStreamCloseRequest struct {
	StreamID string `json:"stream_id"`
	Error    string `json:"error,omitempty"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(abiVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required", 500))
		return 1
	}
	var raw []byte
	if request != nil && requestLen > 0 {
		raw = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	result, err := handleMethod(C.GoString(method), raw)
	if err != nil {
		writeResponse(response, envelopeForError(err))
		return 1
	}
	writeResponse(response, result)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func handleMethod(method string, raw []byte) ([]byte, error) {
	switch method {
	case "plugin.register", "plugin.reconfigure":
		return ok(pluginRegistration())
	case "auth.identifier":
		return ok(map[string]any{"identifier": provider, "identifiers": []string{provider, "mistral"}, "entries": []map[string]string{{"identifier": provider, "name": "Mistral Vibe (OAuth)"}, {"identifier": "mistral", "name": "Mistral Vibe (OAuth)"}}})
	case "auth.parse":
		var req authRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return parseAuth(req)
	case "auth.login.start":
		var req authStartRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return startLogin(req)
	case "auth.login.poll":
		var req authPollRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return pollLogin(req)
	case "auth.refresh":
		var req authRefreshRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return refreshAuth(req)
	case "model.static":
		return ok(modelResponse{Provider: provider, Models: []modelInfo{}})
	case "model.for_auth":
		var req authRefreshRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return modelsForAuth(req)
	case "response.intercept_after":
		var req struct{ Body []byte }
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		body, err := filterCodexCatalog(req.Body)
		if err != nil {
			return nil, err
		}
		return ok(struct{ Body []byte }{Body: body})
	case "executor.identifier":
		return ok(map[string]string{"identifier": provider})
	case "executor.execute":
		var req executorRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return execute(req)
	case "executor.execute_stream":
		var req executorRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return executeStream(req)
	case "executor.count_tokens":
		return ok(executorResponse{Payload: []byte(`{"total_tokens":0}`), Headers: map[string][]string{"content-type": {"application/json"}}})
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method, 500), nil
	}
}

func pluginRegistration() map[string]any {
	return map[string]any{
		"schema_version": schemaVersion,
		"metadata": map[string]any{
			"Name":             "mistral-vibe",
			"Version":          "0.2.0",
			"Author":           "Mistral Vibe Plugin contributors",
			"GitHubRepository": "https://github.com/nulldk/cliproxyapi-mistral-vibe",
			"ConfigFields":     []any{},
		},
		"capabilities": map[string]any{
			"model_provider":          true,
			"auth_provider":           true,
			"executor":                true,
			"executor_model_scope":    "oauth",
			"executor_input_formats":  []string{"chat-completions"},
			"executor_output_formats": []string{"chat-completions"},
			"response_interceptor":    true,
		},
	}
}

// Catalogue checks share the host's credential scheduler and fenced auth updates.
func storedAuthData(stored storedAuth, id string) authData {
	storage, _ := json.Marshal(stored)
	return authData{Provider: provider, ID: id, FileName: id, Label: stored.Label, StorageJSON: storage, Metadata: authMetadata(stored), NextRefreshAfter: nextRefresh(stored)}
}

func rememberCatalog(stored storedAuth) {
	catalogMu.Lock()
	defer catalogMu.Unlock()
	for _, model := range stored.ModelCatalog {
		catalogMetadata[model.ID] = model
	}
}

func refreshCatalog(callbackID string, stored *storedAuth) error {
	stored.CatalogNextCheck = time.Now().Add(catalogRetry).Unix()
	headers := authHeaders(*stored, nil)
	headers["Accept"] = []string{"application/json"}
	resp, err := hostHTTP(callbackID, "GET", apiBaseURL+"/model-catalog?surface=vibe-code", headers, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Mistral model catalogue request failed (HTTP %d)", resp.StatusCode)
	}
	var catalog struct {
		Models json.RawMessage `json:"models"`
	}
	if json.Unmarshal(resp.Body, &catalog) != nil || len(catalog.Models) == 0 || catalog.Models[0] != '[' {
		return fmt.Errorf("invalid Mistral model catalogue")
	}
	var entries []json.RawMessage
	if json.Unmarshal(catalog.Models, &entries) != nil {
		return fmt.Errorf("invalid Mistral model catalogue")
	}
	models := make([]modelInfo, 0, len(entries))
	seen := map[string]bool{}
	for _, raw := range entries {
		var entry struct {
			ID            string `json:"id"`
			Label         string `json:"label"`
			Description   string `json:"description"`
			Recommended   bool   `json:"recommended"`
			ContextLength int64  `json:"max_context_length"`
			Capabilities  struct {
				Chat   bool `json:"completion_chat"`
				Vision bool `json:"vision"`
			} `json:"capabilities"`
		}
		if json.Unmarshal(raw, &entry) != nil || strings.TrimSpace(entry.ID) == "" || strings.TrimSpace(entry.Label) == "" || !entry.Capabilities.Chat || seen[entry.ID] {
			continue
		}
		seen[entry.ID] = true
		modalities := []string{"text"}
		if entry.Capabilities.Vision {
			modalities = append(modalities, "image")
		}
		id := provider + "/" + entry.ID
		models = append(models, modelInfo{ID: id, Object: "model", OwnedBy: provider, DisplayName: entry.Label, Name: id, Description: entry.Description, ContextLength: entry.ContextLength, SupportedInputModalities: modalities, Recommended: entry.Recommended, UserDefined: true})
	}
	sort.SliceStable(models, func(i, j int) bool { return models[i].Recommended && !models[j].Recommended })
	stored.ModelCatalog = models
	stored.CatalogFetchedAt = time.Now().Unix()
	stored.CatalogNextCheck = time.Now().Add(catalogInterval).Unix()
	rememberCatalog(*stored)
	return nil
}

func modelsForAuth(req authRefreshRequest) ([]byte, error) {
	var stored storedAuth
	if err := json.Unmarshal(req.StorageJSON, &stored); err != nil {
		return nil, fmt.Errorf("decode Mistral credentials: %w", err)
	}
	resp := modelResponse{Provider: provider, Models: stored.ModelCatalog}
	// Let auth.refresh renew expired credentials before discovering models.
	if time.Now().Unix() >= stored.CatalogNextCheck && stored.ExpiresAt > time.Now().Add(time.Minute).Unix() {
		err := refreshCatalog(req.HostCallbackID, &stored)
		if err != nil && stored.CatalogFetchedAt == 0 {
			return nil, err
		}
		updated := storedAuthData(stored, req.AuthID)
		resp.AuthUpdate = &updated
	}
	if stored.CatalogFetchedAt == 0 {
		return nil, fmt.Errorf("Mistral model catalogue is awaiting credential refresh")
	}
	rememberCatalog(stored)
	resp.Models = stored.ModelCatalog
	if resp.Models == nil {
		resp.Models = []modelInfo{}
	}
	return ok(resp)
}

func filterCodexCatalog(body []byte) ([]byte, error) {
	var catalog map[string]json.RawMessage
	if json.Unmarshal(body, &catalog) != nil {
		return nil, nil
	}
	if catalog["data"] != nil {
		var entries []map[string]any
		if json.Unmarshal(catalog["data"], &entries) != nil {
			return nil, nil
		}
		changed := false
		catalogMu.RLock()
		for _, entry := range entries {
			id, _ := entry["id"].(string)
			if model, exists := catalogMetadata[id]; exists && entry["owned_by"] == provider {
				entry["display_name"] = model.DisplayName
				entry["context_length"] = model.ContextLength
				entry["max_completion_tokens"] = model.MaxCompletionTokens
				entry["input_modalities"] = model.SupportedInputModalities
				entry["recommended"] = model.Recommended
				changed = true
			}
		}
		catalogMu.RUnlock()
		if !changed {
			return nil, nil
		}
		catalog["data"], _ = json.Marshal(entries)
		return json.Marshal(catalog)
	}
	if catalog["models"] == nil {
		return nil, nil
	}
	var entries []json.RawMessage
	if json.Unmarshal(catalog["models"], &entries) != nil {
		return nil, nil
	}
	filtered := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		var model struct {
			Slug string `json:"slug"`
		}
		if json.Unmarshal(entry, &model) != nil || !strings.HasPrefix(model.Slug, provider+"/") {
			filtered = append(filtered, entry)
		}
	}
	if len(filtered) == len(entries) {
		return nil, nil
	}
	catalog["models"], _ = json.Marshal(filtered)
	return json.Marshal(catalog)
}

func parseAuth(req authRequest) ([]byte, error) {
	var stored storedAuth
	if err := json.Unmarshal(req.RawJSON, &stored); err != nil {
		return ok(authParseResponse{Handled: false})
	}
	kind := strings.ToLower(strings.TrimSpace(stored.Type + " " + stored.Provider))
	if !strings.Contains(kind, "mistral") || (stored.IDToken == "" && stored.AccessToken == "") {
		return ok(authParseResponse{Handled: false})
	}
	fileName := strings.TrimSpace(req.FileName)
	id := fileName
	if id == "" {
		id = filepath.Base(req.Path)
	}
	if id == "" {
		id = provider + ".json"
	}
	label := stored.Label
	if label == "" {
		label = "Mistral Vibe"
	}
	stored.Provider = provider
	stored.Type = provider
	rememberCatalog(stored)
	storage, _ := json.Marshal(stored)
	return ok(authParseResponse{Handled: true, Auth: authData{Provider: provider, ID: id, FileName: fileName, Label: label, StorageJSON: storage, Metadata: authMetadata(stored), NextRefreshAfter: nextRefresh(stored)}})
}

func authMetadata(stored storedAuth) map[string]any {
	return map[string]any{"type": provider, "oauth_provider": provider, "org_id": stored.OrgID, "workspace_id": stored.WorkspaceID, "expires_at": stored.ExpiresAt, "refresh_interval_seconds": 60}
}

func nextRefresh(stored storedAuth) time.Time {
	tokenDue := time.Unix(stored.ExpiresAt, 0).Add(-time.Minute)
	catalogDue := time.Unix(stored.CatalogNextCheck, 0)
	if catalogDue.Before(tokenDue) {
		return catalogDue
	}
	return tokenDue
}

func startLogin(req authStartRequest) ([]byte, error) {
	state, err := randomString(32)
	if err != nil {
		return nil, err
	}
	verifier, err := randomString(32)
	if err != nil {
		return nil, err
	}
	flowMu.Lock()
	flows[state] = oauthFlow{Verifier: verifier, RedirectURI: redirectURI, CreatedAt: time.Now()}
	flowMu.Unlock()
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", "openid offline_access email profile")
	params.Set("audience", "https://api.mistral.ai")
	params.Set("code_challenge_method", "S256")
	params.Set("state", state)
	digest := sha256.Sum256([]byte(verifier))
	params.Set("code_challenge", base64.RawURLEncoding.EncodeToString(digest[:]))
	return ok(authStartResponse{Provider: provider, URL: "https://auth.mistral.ai/oauth2/auth?" + params.Encode(), State: state, ExpiresAt: time.Now().Add(10 * time.Minute), Metadata: map[string]any{"redirect_uri": redirectURI, "auth_dir": req.Host.AuthDir}})
}

func pollLogin(req authPollRequest) ([]byte, error) {
	state := strings.TrimSpace(req.State)
	if state == "" {
		return ok(authPollResponse{Status: "error", Message: "missing OAuth state"})
	}
	flowMu.Lock()
	flow, exists := flows[state]
	flowMu.Unlock()
	if !exists {
		return ok(authPollResponse{Status: "error", Message: "OAuth session expired; sign in again"})
	}
	callbackPath, raw, err := readCallback(req.Host.AuthDir, req.Provider, state)
	if os.IsNotExist(err) {
		return ok(authPollResponse{Status: "pending"})
	}
	if err != nil {
		return nil, fmt.Errorf("read OAuth callback: %w", err)
	}
	var callback callbackPayload
	if err := json.Unmarshal(raw, &callback); err != nil {
		return nil, fmt.Errorf("decode OAuth callback: %w", err)
	}
	_ = os.Remove(callbackPath)
	if callback.Error != "" {
		return ok(authPollResponse{Status: "error", Message: "Mistral OAuth failed: " + callback.Error})
	}
	if callback.State != "" && callback.State != state {
		return ok(authPollResponse{Status: "error", Message: "Mistral OAuth state mismatch"})
	}
	if callback.Code == "" {
		return ok(authPollResponse{Status: "error", Message: "Mistral callback did not contain an authorization code"})
	}
	tokens, err := exchangeTokens(req.HostCallbackID, map[string]string{"grant_type": "authorization_code", "code": callback.Code, "redirect_uri": flow.RedirectURI, "code_verifier": flow.Verifier}, nil)
	if err != nil {
		return nil, err
	}
	auth, err := tokenAuth(req.HostCallbackID, tokens, "Mistral Vibe", provider+".json", nil)
	if err != nil {
		return nil, err
	}
	flowMu.Lock()
	delete(flows, state)
	flowMu.Unlock()
	return ok(authPollResponse{Status: "success", Message: "Mistral OAuth login complete", Auth: auth})
}

func refreshAuth(req authRefreshRequest) ([]byte, error) {
	var stored storedAuth
	if err := json.Unmarshal(req.StorageJSON, &stored); err != nil {
		return nil, fmt.Errorf("decode Mistral credentials: %w", err)
	}
	fileName := req.AuthID
	if !strings.HasSuffix(strings.ToLower(fileName), ".json") {
		fileName += ".json"
	}
	var auth authData
	if stored.ExpiresAt <= time.Now().Add(time.Minute).Unix() {
		if stored.RefreshToken == "" {
			return nil, fmt.Errorf("Mistral refresh token is missing; sign in again")
		}
		tokens, err := exchangeTokens(req.HostCallbackID, map[string]string{"grant_type": "refresh_token", "refresh_token": stored.RefreshToken}, &stored)
		if err != nil {
			return nil, err
		}
		auth, err = tokenAuth(req.HostCallbackID, tokens, stored.Label, fileName, &stored)
		if err != nil {
			return nil, err
		}
	} else {
		// A catalogue failure must not invalidate working credentials or their cache.
		if time.Now().Unix() >= stored.CatalogNextCheck {
			_ = refreshCatalog(req.HostCallbackID, &stored)
		}
		auth = storedAuthData(stored, fileName)
	}
	return ok(authRefreshResponse{Auth: auth, NextRefreshAfter: auth.NextRefreshAfter})
}

func tokenAuth(callbackID string, tokens tokenResponse, label, fileName string, previous *storedAuth) (authData, error) {
	if tokens.IDToken == "" {
		return authData{}, fmt.Errorf("Mistral did not return an OIDC ID token")
	}
	claims, err := verifyIDToken(tokens.IDToken)
	if err != nil {
		return authData{}, err
	}
	workspaces, err := discoverWorkspaces(callbackID, tokens.IDToken)
	if err != nil {
		return authData{}, err
	}
	var workspace map[string]any
	if len(workspaces) > 0 {
		workspace = workspaces[0]
	}
	workspaceID, _ := workspace["id"].(string)
	orgID, _ := workspace["organization_id"].(string)
	if previous != nil {
		if previous.WorkspaceID != "" {
			workspaceID = previous.WorkspaceID
		}
		if previous.OrgID != "" {
			orgID = previous.OrgID
		}
	}
	if workspaceID == "" || orgID == "" {
		return authData{}, fmt.Errorf("no accessible Mistral workspace found")
	}
	if fileName == ".json" || fileName == "" {
		fileName = provider + ".json"
	}
	stored := storedAuth{Type: provider, Provider: provider, AccessToken: tokens.AccessToken, IDToken: tokens.IDToken, RefreshToken: tokens.RefreshToken, ExpiresAt: time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second).Unix(), OrgID: orgID, WorkspaceID: workspaceID, Label: label}
	if previous != nil {
		stored.ModelCatalog = previous.ModelCatalog
		stored.CatalogFetchedAt = previous.CatalogFetchedAt
		stored.CatalogNextCheck = previous.CatalogNextCheck
	}
	if time.Now().Unix() >= stored.CatalogNextCheck {
		_ = refreshCatalog(callbackID, &stored)
	}
	storage, _ := json.Marshal(stored)
	email, _ := claims["email"].(string)
	if email != "" {
		label = "Mistral Vibe (" + email + ")"
		stored.Label = label
		storage, _ = json.Marshal(stored)
	}
	return authData{Provider: provider, ID: fileName, FileName: fileName, Label: label, StorageJSON: storage, Metadata: authMetadata(stored), NextRefreshAfter: nextRefresh(stored)}, nil
}

func exchangeTokens(callbackID string, fields map[string]string, previous *storedAuth) (tokenResponse, error) {
	body := url.Values{}
	body.Set("client_id", clientID)
	for key, value := range fields {
		body.Set(key, value)
	}
	resp, err := hostHTTP(callbackID, "POST", tokenURL, map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(body.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return tokenResponse{}, fmt.Errorf("Mistral OAuth token request failed (HTTP %d); sign in again", resp.StatusCode)
	}
	var tokens tokenResponse
	if err := json.Unmarshal(resp.Body, &tokens); err != nil {
		return tokenResponse{}, fmt.Errorf("invalid Mistral OAuth token response")
	}
	if tokens.AccessToken == "" || tokens.ExpiresIn <= 30 || !strings.EqualFold(tokens.TokenType, "bearer") {
		return tokenResponse{}, fmt.Errorf("Mistral returned an invalid OAuth token response")
	}
	if tokens.RefreshToken == "" && previous != nil {
		tokens.RefreshToken = previous.RefreshToken
	}
	if tokens.RefreshToken == "" || tokens.IDToken == "" {
		return tokenResponse{}, fmt.Errorf("Mistral did not return a refresh token and ID token; sign in again")
	}
	return tokens, nil
}

func verifyIDToken(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid Mistral ID token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid Mistral ID token")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid Mistral ID token")
	}
	if claims["iss"] != "https://auth.mistral.ai" {
		return nil, fmt.Errorf("invalid Mistral ID token issuer")
	}
	audienceOK := false
	switch audience := claims["aud"].(type) {
	case string:
		audienceOK = audience == clientID
	case []any:
		for _, value := range audience {
			if value == clientID {
				audienceOK = true
				break
			}
		}
	}
	if !audienceOK {
		return nil, fmt.Errorf("invalid Mistral ID token audience")
	}
	if exp, ok := claims["exp"].(float64); !ok || exp <= float64(time.Now().Unix()) {
		return nil, fmt.Errorf("expired Mistral ID token")
	}
	return claims, nil
}

func discoverWorkspaces(callbackID, idToken string) ([]map[string]any, error) {
	resp, err := hostHTTP(callbackID, "GET", workspaceURL, map[string][]string{"Authorization": {"Bearer " + idToken}}, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Mistral workspace discovery failed (HTTP %d)", resp.StatusCode)
	}
	var payload struct {
		Workspaces []map[string]any `json:"workspaces"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		return nil, fmt.Errorf("invalid Mistral workspace response")
	}
	return payload.Workspaces, nil
}

func execute(req executorRequest) ([]byte, error) {
	stored, err := credentials(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	body := req.Payload
	if len(body) == 0 {
		body = req.OriginalRequest
	}
	body, err = ensureModel(body, req.Model, false)
	if err != nil {
		return nil, err
	}
	headers := authHeaders(stored, req.Headers)
	resp, err := hostHTTP(req.HostCallbackID, "POST", apiBaseURL+"/chat/completions", headers, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, upstreamError(resp.StatusCode, resp.Headers)
	}
	for key := range resp.Headers {
		if strings.EqualFold(key, "Content-Length") {
			delete(resp.Headers, key)
		}
	}
	return ok(executorResponse{Payload: normalizeCompletion(resp.Body), Headers: resp.Headers})
}

func executeStream(req executorRequest) ([]byte, error) {
	stored, err := credentials(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	body := req.Payload
	if len(body) == 0 {
		body = req.OriginalRequest
	}
	body, err = ensureModel(body, req.Model, true)
	if err != nil {
		return nil, err
	}
	headers := authHeaders(stored, req.Headers)
	resp, err := hostHTTPStream(req.HostCallbackID, "POST", apiBaseURL+"/chat/completions", headers, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		_ = hostHTTPStreamClose(resp.StreamID)
		return nil, upstreamError(resp.StatusCode, resp.Headers)
	}
	go forwardStream(resp.StreamID, req.StreamID)
	return ok(executorStreamResponse{Headers: resp.Headers})
}

func forwardStream(upstreamID, downstreamID string) {
	defer func() { _ = hostHTTPStreamClose(upstreamID); _ = hostStreamClose(downstreamID, "") }()
	var normalizer sseNormalizer
	for {
		raw, err := callHost("host.http.stream_read", hostHTTPStreamReadRequest{StreamID: upstreamID})
		if err != nil {
			_ = hostStreamClose(downstreamID, err.Error())
			return
		}
		var chunk hostHTTPStreamReadResponse
		if err := json.Unmarshal(raw, &chunk); err != nil {
			_ = hostStreamClose(downstreamID, "invalid Mistral stream response")
			return
		}
		if chunk.Error != "" {
			_ = hostStreamClose(downstreamID, chunk.Error)
			return
		}
		if len(chunk.Payload) > 0 {
			if payload := normalizer.write(chunk.Payload); len(payload) > 0 {
				if err := hostStreamEmit(downstreamID, payload); err != nil {
					return
				}
			}
		}
		if chunk.Done {
			if len(normalizer.pending) > 0 {
				_ = hostStreamEmit(downstreamID, normalizeSSELine(normalizer.pending))
			}
			return
		}
	}
}

// Mistral can return typed text/thinking blocks where OpenAI clients expect strings.
func normalizeCompletion(body []byte) []byte {
	var response map[string]any
	if json.Unmarshal(body, &response) != nil {
		return body
	}
	choices, _ := response["choices"].([]any)
	changed := false
	for _, raw := range choices {
		choice, _ := raw.(map[string]any)
		for _, key := range []string{"message", "delta"} {
			message, _ := choice[key].(map[string]any)
			blocks, ok := message["content"].([]any)
			if !ok {
				continue
			}
			var text, thinking strings.Builder
			for _, rawBlock := range blocks {
				block, _ := rawBlock.(map[string]any)
				switch block["type"] {
				case "text":
					value, _ := block["text"].(string)
					text.WriteString(value)
				case "thinking":
					switch value := block["thinking"].(type) {
					case string:
						thinking.WriteString(value)
					case []any:
						for _, rawPart := range value {
							part, _ := rawPart.(map[string]any)
							value, _ := part["text"].(string)
							thinking.WriteString(value)
						}
					}
				}
			}
			message["content"] = text.String()
			if thinking.Len() > 0 {
				existing, _ := message["reasoning_content"].(string)
				message["reasoning_content"] = existing + thinking.String()
			}
			changed = true
		}
	}
	if !changed {
		return body
	}
	result, err := json.Marshal(response)
	if err != nil {
		return body
	}
	return result
}

type sseNormalizer struct{ pending []byte }

func (n *sseNormalizer) write(payload []byte) []byte {
	n.pending = append(n.pending, payload...)
	var out []byte
	for {
		end := bytes.IndexByte(n.pending, '\n')
		if end < 0 {
			break
		}
		out = append(out, normalizeSSELine(n.pending[:end])...)
		out = append(out, '\n')
		n.pending = n.pending[end+1:]
	}
	return out
}

func normalizeSSELine(line []byte) []byte {
	if !bytes.HasPrefix(line, []byte("data:")) {
		return line
	}
	payload := bytes.TrimSpace(line[len("data:"):])
	if !json.Valid(payload) {
		return line
	}
	return append([]byte("data: "), normalizeCompletion(payload)...)
}

type httpStatusError struct {
	status            int
	message           string
	retryAfterSeconds int
}

func (e httpStatusError) Error() string          { return e.message }
func (e httpStatusError) StatusCode() int        { return e.status }
func (e httpStatusError) RetryAfterSeconds() int { return e.retryAfterSeconds }

func upstreamError(status int, headers map[string][]string) error {
	return httpStatusError{status: status, message: fmt.Sprintf("Mistral API returned HTTP %d", status), retryAfterSeconds: parseRetryAfter(headers, time.Now())}
}

func parseRetryAfter(headers map[string][]string, now time.Time) int {
	for name, values := range headers {
		if !strings.EqualFold(name, "Retry-After") {
			continue
		}
		for _, raw := range values {
			value := strings.TrimSpace(raw)
			if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
				if seconds > 0 && seconds <= int64((time.Duration(1<<63-1))/time.Second) {
					return int(seconds)
				}
				continue
			}
			if date, err := http.ParseTime(value); err == nil && date.After(now) {
				delay := date.Sub(now)
				seconds := delay / time.Second
				if delay%time.Second > 0 {
					seconds++
				}
				return int(seconds)
			}
		}
	}
	return 0
}

func envelopeForError(err error) []byte {
	detail := &pluginError{Code: "plugin_error", Message: err.Error(), HTTPStatus: 500}
	var status interface{ StatusCode() int }
	if errors.As(err, &status) && status.StatusCode() > 0 {
		detail.HTTPStatus = status.StatusCode()
	}
	var retry interface{ RetryAfterSeconds() int }
	if errors.As(err, &retry) && retry.RetryAfterSeconds() > 0 {
		detail.RetryAfterSeconds = retry.RetryAfterSeconds()
	}
	raw, _ := json.Marshal(envelope{OK: false, Error: detail})
	return raw
}

func credentials(raw []byte) (storedAuth, error) {
	var stored storedAuth
	if err := json.Unmarshal(raw, &stored); err != nil {
		return stored, fmt.Errorf("decode Mistral credentials: %w", err)
	}
	if stored.IDToken == "" && stored.AccessToken == "" {
		return stored, fmt.Errorf("Mistral OAuth credential has no token")
	}
	return stored, nil
}

func authHeaders(stored storedAuth, existing map[string][]string) map[string][]string {
	headers := map[string][]string{}
	for key, values := range existing {
		headers[key] = append([]string(nil), values...)
	}
	token := stored.IDToken
	if token == "" {
		token = stored.AccessToken
	}
	headers["Authorization"] = []string{"Bearer " + token}
	headers["Content-Type"] = []string{"application/json"}
	headers["Accept"] = []string{"text/event-stream"}
	headers["x-external-organization-id"] = []string{stored.OrgID}
	headers["x-external-workspace-id"] = []string{stored.WorkspaceID}
	return headers
}

func ensureModel(body []byte, model string, stream bool) ([]byte, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("invalid chat completion payload: %w", err)
	}
	if strings.TrimSpace(model) != "" {
		payload["model"] = strings.TrimPrefix(model, provider+"/")
	}
	payload["stream"] = stream
	delete(payload, "store")
	messages, _ := payload["messages"].([]any)
	for _, raw := range messages {
		message, _ := raw.(map[string]any)
		if message["role"] != "assistant" {
			continue
		}
		thinking, _ := message["reasoning_content"].(string)
		delete(message, "reasoning_content")
		if thinking == "" {
			continue
		}
		blocks := []any{map[string]any{"type": "thinking", "thinking": []any{map[string]any{"type": "text", "text": thinking}}, "closed": true}}
		switch content := message["content"].(type) {
		case string:
			if content != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": content})
			}
		case []any:
			blocks = append(blocks, content...)
		}
		message["content"] = blocks
	}
	return json.Marshal(payload)
}

func readCallback(authDir, requestedProvider, state string) (string, []byte, error) {
	providers := []string{provider, "mistral"}
	requestedProvider = strings.ToLower(strings.TrimSpace(requestedProvider))
	if requestedProvider == "mistral" || requestedProvider == provider {
		providers = append([]string{requestedProvider}, providers...)
	}
	seen := map[string]bool{}
	for _, candidate := range providers {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		path := filepath.Join(authDir, ".oauth-"+candidate+"-"+state+".oauth")
		raw, err := os.ReadFile(path)
		if err == nil {
			return path, raw, nil
		}
		if !os.IsNotExist(err) {
			return path, nil, err
		}
	}
	return filepath.Join(authDir, ".oauth-"+provider+"-"+state+".oauth"), nil, os.ErrNotExist
}

func randomString(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hostHTTP(callbackID, method, target string, headers map[string][]string, body []byte) (hostHTTPResponse, error) {
	if headers == nil {
		headers = map[string][]string{}
	}
	headers["User-Agent"] = []string{"Google"}
	raw, err := callHost("host.http.do", map[string]any{"host_callback_id": callbackID, "method": method, "url": target, "headers": headers, "body": body})
	if err != nil {
		return hostHTTPResponse{}, err
	}
	var resp hostHTTPResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return resp, fmt.Errorf("decode host HTTP response: %w", err)
	}
	return resp, nil
}
func hostHTTPStream(callbackID, method, target string, headers map[string][]string, body []byte) (hostHTTPStreamResponse, error) {
	if headers == nil {
		headers = map[string][]string{}
	}
	headers["User-Agent"] = []string{"Google"}
	raw, err := callHost("host.http.do_stream", map[string]any{"host_callback_id": callbackID, "method": method, "url": target, "headers": headers, "body": body})
	if err != nil {
		return hostHTTPStreamResponse{}, err
	}
	var resp hostHTTPStreamResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return resp, fmt.Errorf("decode host HTTP stream response: %w", err)
	}
	return resp, nil
}
func hostHTTPStreamClose(streamID string) error {
	_, err := callHost("host.http.stream_close", hostHTTPStreamCloseRequest{StreamID: streamID})
	return err
}
func hostStreamEmit(streamID string, payload []byte) error {
	_, err := callHost("host.stream.emit", hostStreamEmitRequest{StreamID: streamID, Payload: payload})
	return err
}
func hostStreamClose(streamID, message string) error {
	_, err := callHost("host.stream.close", hostStreamCloseRequest{StreamID: streamID, Error: message})
	return err
}

func callHost(method string, request any) ([]byte, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var req *C.uint8_t
	if len(raw) > 0 {
		req = (*C.uint8_t)(C.CBytes(raw))
		defer C.free(unsafe.Pointer(req))
	}
	var response C.cliproxy_buffer
	if C.call_host_api(cMethod, req, C.size_t(len(raw)), &response) != 0 {
		return nil, fmt.Errorf("host callback %s failed", method)
	}
	defer C.free_host_buffer(response.ptr, response.len)
	if response.ptr == nil || response.len == 0 {
		return nil, nil
	}
	outerRaw := C.GoBytes(response.ptr, C.int(response.len))
	var outer envelope
	if err := json.Unmarshal(outerRaw, &outer); err != nil {
		return nil, fmt.Errorf("decode host callback %s: %w", method, err)
	}
	if !outer.OK {
		if outer.Error != nil {
			return nil, fmt.Errorf("host callback %s: %s", method, outer.Error.Message)
		}
		return nil, fmt.Errorf("host callback %s failed", method)
	}
	return append([]byte(nil), outer.Result...), nil
}

func ok(result any) ([]byte, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}
func errorEnvelope(code, message string, status int) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &pluginError{Code: code, Message: message, HTTPStatus: status}})
	return raw
}
func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
