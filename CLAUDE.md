# FigmaLint — Claude Code Project Context

## What This Is
A Figma plugin that analyzes design components using LLMs. Runs in the **Figma plugin sandbox** (main thread = `code.ts`, UI thread = `ui-enhanced.html`). Built with esbuild, TypeScript.

## Build
```bash
npm run build   # clean + bundle + copy assets to dist/
```
Output: `dist/code.js` + `dist/ui-enhanced.html` + `dist/manifest.json`

## Architecture: Multi-Provider LLM Abstraction
`src/api/providers/` is the core abstraction layer:

| File | Role |
|---|---|
| `types.ts` | `ProviderId`, `LLMModel`, `LLMProvider` interface, model registries, utility fns |
| `index.ts` | Provider registry, `callProvider()` (unified fetch), storage helpers |
| `anthropic.ts` | Anthropic direct API |
| `openai.ts` | OpenAI |
| `google.ts` | Google Gemini |
| `bedrock.ts` | AWS Bedrock (Claude via IAM) |

**Adding a provider** requires touching: `types.ts` (ProviderId union + models), `index.ts` (registry + callProvider special case), new provider file, `ui-enhanced.html` (dropdown + models + JS), `message-handler.ts` (`isValidApiKeyFormat`).

## Figma Plugin Sandbox Constraints
The plugin main thread (`code.ts`) runs in a **heavily sandboxed JS environment**. Missing globals that exist in browsers/Node:
- ❌ `URL` constructor — parse URLs manually with string ops
- ❌ `TextEncoder` — use a manual UTF-8 encoder
- ❌ `crypto.subtle` — use pure-JS crypto implementations
- ✅ `fetch`, `Uint8Array`, `DataView`, `Uint32Array`, `Date`, `JSON`

## AWS Bedrock Provider Notes
- Credentials stored as JSON string: `{"accessKeyId":"...","secretAccessKey":"...","region":"us-east-1"}`
- Key stored under `bedrock-api-key` in Figma `clientStorage`
- SigV4 signing is **pure JS** (no Web Crypto) — see `bedrock.ts` `sha256Bytes` / `hmacSHA256`
- **Inference profiles required** for newer Claude models — `callProvider` auto-prepends region prefix: `us.anthropic.*`, `eu.anthropic.*`, `ap.anthropic.*`
- Default model: `anthropic.claude-sonnet-4-5-20250929-v1:0` → sent as `us.anthropic.claude-sonnet-4-5-20250929-v1:0`
- SigV4 canonical URI: each path segment gets SigV4-re-encoded (`:` → `%3A` → `%253A`)
- `isValidApiKeyFormat()` exists in **both** `types.ts` AND `src/ui/message-handler.ts` — both must be kept in sync when adding providers

## Key Gotchas
- `message-handler.ts` has its own `isValidApiKeyFormat()` switch — easy to miss when adding a provider
- Bedrock SigV4: the `%` in URL-encoded path (e.g. `%3A`) must be re-encoded to `%25` for the canonical URI — AWS double-encodes the path
- AWS Bedrock model access must be explicitly enabled per-region in the Bedrock console
- IAM policy needs `bedrock:InvokeModel` on `arn:aws:bedrock:*::foundation-model/anthropic.*`
