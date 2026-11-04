# Mistral Vibe for CLIProxyAPI

Native CLIProxyAPI provider plugin for Mistral Vibe subscriptions. It exposes an OpenAI-compatible Chat Completions API while CLIProxyAPI owns credentials, transport, retries, and cooldowns.

Inference requires a **Vibe-scoped key** obtained through the official Vibe sign-in or key page. OAuth user tokens alone consume the separate API budget, even when the account has a Vibe subscription. The plugin refuses OAuth-only inference to prevent unexpected API usage. A regular workspace API key is not a Vibe key.

Store the Vibe key in a private JSON file in CLIProxyAPI's auth directory (mode `0600`):

```json
{"type":"mistral-vibe","api_key":"<VIBE_SCOPED_KEY>"}
```

For an existing OAuth credential, add `api_key` to that file instead of creating a second credential. The key determines its own workspace; OAuth workspace headers are not forwarded with it. Key credentials refresh the model catalogue without renewing or expiring with an unused OAuth token. All plugin HTTP requests use `User-Agent: Mistral-Vibe/CLIProxyAPI`.

Implemented from the authentication flow documented by [omp-mistral-vibe](https://github.com/Microck/omp-mistral-vibe). This is an independent Go implementation, not an official Mistral integration.

## Features

- OAuth authorization code flow with PKCE, workspace discovery, and token renewal.
- Namespaced model IDs under the `mistral-vibe` provider.
- Streaming, tool calls, and conversion between Mistral thinking blocks and OpenAI reasoning fields.
- HTTP status and `Retry-After` propagation to CLIProxyAPI, including HTTP-date headers.
- Mistral models stay out of the Codex-specific model catalog.

Models are discovered from Mistral's authenticated `GET /v1/model-catalog?surface=vibe-code` endpoint, the same catalogue used by the [official Vibe client](https://github.com/mistralai/mistral-vibe). `deepseek-v4-1-flash-1017` is also registered statically because it supports Vibe keys but is absent from the catalogue. The catalogue is checked at sign-in and every 30 minutes through CLIProxyAPI's credential refresh scheduler. Unexpired OAuth tokens are reused for catalogue checks. The host may invoke credential refresh more frequently; the plugin reuses its cached catalogue until its next check is due, including during token renewal.

The last successful catalogue is persisted with the credential, survives restarts, and is retained on transient errors; failed checks are retried after one minute. Successful responses replace the complete list, including removals and an empty catalogue. Only models supporting chat completions are registered. Names, context limits, and image support come from the catalogue. Client adapters can read these fields from `/v1/models`.

## Build and install

Requires Go 1.23 or newer, a C compiler, and CLIProxyAPI with native plugin ABI 1 / schema 10 support. Verified with CLIProxyAPI 8.0.52 on Linux.

```sh
CGO_ENABLED=1 go build -buildmode=c-shared -trimpath -buildvcs=false \
  -ldflags='-s -w' -o mistral-vibe.so .
install -Dm755 mistral-vibe.so ./plugins/mistral-vibe.so
```

Enable the plugin in your CLIProxyAPI configuration:

```yaml
plugins:
  enabled: true
  dir: ./plugins
  configs:
    mistral-vibe:
      enabled: true
```

Restart CLIProxyAPI after replacing the shared library. Build on the target architecture, or configure a suitable C cross-compiler.

## OAuth sign in (account discovery only)

This optional flow discovers the account and models; add a Vibe-scoped `api_key` before using inference.

Set `CLIPROXY_URL` to your gateway URL and `MANAGEMENT_KEY` to its management key. The example uses the default local gateway address.

```sh
export CLIPROXY_URL=http://localhost:8317
curl -A Google -fsS -H "Authorization: Bearer $MANAGEMENT_KEY" \
  "$CLIPROXY_URL/v8/management/oauth/auth-url?provider=mistral-vibe"
```

Open the returned `url` in your browser and retain the returned `state`. Mistral redirects to the registered loopback URI `http://127.0.0.1:8766/callback`. This URI is part of the OAuth application flow; it is not a gateway hosting address. The plugin does not start a browser callback listener.

Copy that complete redirect URL into `CALLBACK_URL`, then submit it to your gateway:

```sh
jq -n --arg url "$CALLBACK_URL" \
  '{provider:"mistral-vibe",redirect_url:$url}' |
  curl -A Google -fsS -H "Authorization: Bearer $MANAGEMENT_KEY" \
    -H 'Content-Type: application/json' --data-binary @- \
    "$CLIPROXY_URL/v8/management/oauth/callback"

curl -A Google -fsS -H "Authorization: Bearer $MANAGEMENT_KEY" \
  "$CLIPROXY_URL/v8/management/oauth/status?state=$STATE"
```

The status request completes the exchange and saves the credential through CLIProxyAPI. Keep callback URLs and credential files private. OAuth application identifiers embedded in the source are public client identifiers, not account credentials.

## Retry behavior

The plugin does not run a separate retry loop. Both completion modes return upstream HTTP status and positive `Retry-After` guidance through the native plugin error envelope. Missing, invalid, and expired retry hints are omitted. CLIProxyAPI decides whether to retry, switch credentials, or wait according to its routing configuration. Hosts that predate retry-hint support may ignore this optional field. Errors after streaming has started cannot transparently replay already delivered output.

## Developing integrations

This repository contains only the reusable plugin. Host configuration, deployment tooling, and application adapters belong in the consuming project. Consumers can pin this repository to a commit and advance that pin after publishing an update; local development can override the source without maintaining a copied implementation.
