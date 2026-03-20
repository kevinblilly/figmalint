# Session: Add AWS Bedrock as AI Provider
**Date:** 2026-03-20
**Branch:** main

## Goal
Add AWS Bedrock as a fourth LLM provider so Claude models can be accessed via IAM credentials instead of an Anthropic API key — useful for enterprise licensing and per-user IAM credential distribution.

## What Was Built

### New file: `src/api/providers/bedrock.ts`
Full `BedrockProvider` implementation with pure-JS SigV4 request signing. The Figma plugin sandbox lacks `URL`, `TextEncoder`, and `crypto.subtle`, so all three were replaced:
- `URL` → manual string parsing (`indexOf('/')`)
- `TextEncoder` → manual UTF-8 encoder
- `crypto.subtle` → pure-JS SHA-256 (`sha256Bytes`) and HMAC-SHA256 (`hmacSHA256`) using `Uint32Array` / `DataView`

### Modified files
- `src/api/providers/types.ts` — added `'bedrock'` to `ProviderId`, `BEDROCK_MODELS`, `DEFAULT_MODELS`, `getAllModels`, `getModelsForProvider`, `validateApiKeyFormat`
- `src/api/providers/index.ts` — added bedrock to registry/meta, added special-case block in `callProvider()` for dynamic endpoint + SigV4 signing + inference profile prefix
- `src/ui/message-handler.ts` — added `case 'bedrock':` to `isValidApiKeyFormat()` (this was a separate copy of validation logic that was initially missed)
- `manifest.json` — added `"https://*.amazonaws.com"` to `allowedDomains`
- `ui-enhanced.html` — provider dropdown, Bedrock credential fields (region + access key ID + secret), model optgroup, `providerConfig`, `handleProviderChange`, `handleSaveApiKey`, `handleApiKeyStatus`

## Bugs Hit (in order)

| Error | Root Cause | Fix |
|---|---|---|
| "Invalid API key format" on Save Key | `message-handler.ts` has its own `isValidApiKeyFormat()` with no `bedrock` case | Added `case 'bedrock':` JSON parse check |
| `URL is not a constructor` | Figma sandbox lacks `URL` | Replace `new URL(url)` with manual string split |
| `TextEncoder is not a constructor` | Figma sandbox lacks `TextEncoder` | Manual UTF-8 encoder |
| `Cannot read properties of undefined (reading 'subtle')` | `crypto.subtle` unavailable in plugin sandbox | Pure-JS SHA-256 + HMAC-SHA256 |
| SigV4 signature mismatch (403) | Canonical URI path not re-encoded per SigV4 spec | Per-segment `sigV4Encode()` — `%3A` → `%253A` |
| "on-demand throughput isn't supported" (400) | Newer Claude models require inference profiles | Auto-prepend region prefix: `us.anthropic.*` |

## AWS Setup Required
1. Bedrock console → Model access → enable models per-region
2. IAM user with `AmazonBedrockFullAccess` or custom policy with `bedrock:InvokeModel`
3. Generate access key → enter in plugin as Access Key ID + Secret Access Key

## Default Model
`anthropic.claude-sonnet-4-5-20250929-v1:0` (sent to API as `us.anthropic.claude-sonnet-4-5-20250929-v1:0` for `us-east-1`)
