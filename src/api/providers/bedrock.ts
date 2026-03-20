/**
 * AWS Bedrock Provider Implementation
 *
 * Implements the LLMProvider interface for AWS Bedrock's Claude models.
 * Uses AWS Signature Version 4 (SigV4) for request signing via Web Crypto API.
 */

import {
  LLMProvider,
  LLMModel,
  RequestConfig,
  LLMResponse,
  ApiKeyValidationResult,
  RequestHeaders,
  LLMError,
  LLMErrorCode,
} from './types';

// =============================================================================
// Credentials Types
// =============================================================================

/**
 * AWS credentials for Bedrock access
 */
export interface BedrockCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

// =============================================================================
// Credential Parsing
// =============================================================================

/**
 * Parse and validate Bedrock credentials from a JSON string
 *
 * @param jsonStr - JSON string containing AWS credentials
 * @returns Parsed BedrockCredentials
 * @throws Error if JSON is invalid or required fields are missing
 */
export function parseBedrockCredentials(jsonStr: string): BedrockCredentials {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new Error('Invalid credentials: must be valid JSON');
  }

  const { accessKeyId, secretAccessKey, region } = parsed as unknown as BedrockCredentials;

  if (!accessKeyId || typeof accessKeyId !== 'string' || !accessKeyId.trim()) {
    throw new Error('Missing or empty accessKeyId');
  }
  if (!secretAccessKey || typeof secretAccessKey !== 'string' || !secretAccessKey.trim()) {
    throw new Error('Missing or empty secretAccessKey');
  }
  if (!region || typeof region !== 'string' || !region.trim()) {
    throw new Error('Missing or empty region');
  }

  return {
    accessKeyId: accessKeyId.trim(),
    secretAccessKey: secretAccessKey.trim(),
    region: region.trim(),
  };
}

// =============================================================================
// SigV4 Signing
// =============================================================================

/**
 * Manual UTF-8 encoder — Figma plugin sandbox lacks TextEncoder
 */
function encodeUtf8(str: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xC0 | (code >> 6), 0x80 | (code & 0x3F));
    } else if (code >= 0xD800 && code <= 0xDBFF) {
      const lo = str.charCodeAt(++i);
      code = 0x10000 + ((code - 0xD800) << 10) + (lo - 0xDC00);
      bytes.push(
        0xF0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3F),
        0x80 | ((code >> 6) & 0x3F),
        0x80 | (code & 0x3F)
      );
    } else {
      bytes.push(0xE0 | (code >> 12), 0x80 | ((code >> 6) & 0x3F), 0x80 | (code & 0x3F));
    }
  }
  return new Uint8Array(bytes);
}

// SHA-256 round constants
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr32(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

/**
 * Pure-JS SHA-256 — no Web Crypto API needed
 */
function sha256Bytes(data: Uint8Array): Uint8Array {
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const len = data.length;
  const paddedLen = Math.ceil((len + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 4, (len * 8) >>> 0, false);
  view.setUint32(paddedLen - 8, Math.floor(len / 0x20000000) >>> 0, false);

  const w = new Uint32Array(64);
  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  const result = new Uint8Array(32);
  const rv = new DataView(result.buffer);
  rv.setUint32(0, h0, false);  rv.setUint32(4, h1, false);
  rv.setUint32(8, h2, false);  rv.setUint32(12, h3, false);
  rv.setUint32(16, h4, false); rv.setUint32(20, h5, false);
  rv.setUint32(24, h6, false); rv.setUint32(28, h7, false);
  return result;
}

function sha256Hex(message: string): string {
  return Array.from(sha256Bytes(encodeUtf8(message)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Pure-JS HMAC-SHA256
 */
function hmacSHA256(key: Uint8Array | string, message: Uint8Array | string): Uint8Array {
  const BLOCK = 64;
  let k = typeof key === 'string' ? encodeUtf8(key) : key;
  if (k.length > BLOCK) k = sha256Bytes(k);

  const kPadded = new Uint8Array(BLOCK);
  kPadded.set(k);

  const ipad = new Uint8Array(BLOCK);
  const opad = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    ipad[i] = kPadded[i] ^ 0x36;
    opad[i] = kPadded[i] ^ 0x5C;
  }

  const msg = typeof message === 'string' ? encodeUtf8(message) : message;

  const inner = new Uint8Array(BLOCK + msg.length);
  inner.set(ipad); inner.set(msg, BLOCK);
  const innerHash = sha256Bytes(inner);

  const outer = new Uint8Array(BLOCK + 32);
  outer.set(opad); outer.set(innerHash, BLOCK);
  return sha256Bytes(outer);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Derive the SigV4 signing key via HMAC chaining
 */
function getSignatureKey(secret: string, date: string, region: string, service: string): Uint8Array {
  const kDate    = hmacSHA256('AWS4' + secret, date);
  const kRegion  = hmacSHA256(kDate, region);
  const kService = hmacSHA256(kRegion, service);
  return hmacSHA256(kService, 'aws4_request');
}

/**
 * SigV4 URI encoding: encode every byte except A-Za-z0-9 - . _ ~
 * Applied to each path segment in the canonical URI (not to the / separators).
 * This means a path already containing %3A will have its % encoded to %25, giving %253A.
 */
function sigV4Encode(str: string): string {
  let result = '';
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (
      (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
      ch === '-' || ch === '.' || ch === '_' || ch === '~'
    ) {
      result += ch;
    } else {
      result += '%' + str.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0');
    }
  }
  return result;
}

/**
 * Sign an AWS Bedrock request using Signature Version 4 (pure JS, no Web Crypto)
 *
 * @param credentials - AWS credentials
 * @param method - HTTP method (POST)
 * @param url - Full request URL
 * @param body - Request body string
 * @returns Headers containing Authorization, x-amz-date, and x-amz-content-sha256
 */
export function signBedrockRequest(
  credentials: BedrockCredentials,
  method: string,
  url: string,
  body: string
): { Authorization: string; 'x-amz-date': string; 'x-amz-content-sha256': string } {
  const service = 'bedrock';
  // Parse URL manually — Figma plugin sandbox lacks URL constructor
  const withoutProtocol = url.replace(/^https?:\/\//, '');
  const slashIndex = withoutProtocol.indexOf('/');
  const host = slashIndex === -1 ? withoutProtocol : withoutProtocol.slice(0, slashIndex);
  const rawPath = slashIndex === -1 ? '/' : withoutProtocol.slice(slashIndex);

  // SigV4 canonical URI: re-encode each path segment per the SigV4 spec.
  // Each segment is SigV4-encoded (everything except A-Za-z0-9-._~), so a
  // URL-encoded % in the raw path (e.g. %3A) becomes %25 → %253A.
  const canonicalUri = rawPath.split('/').map(sigV4Encode).join('/');
  const canonicalQueryString = '';

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);

  const payloadHash = sha256Hex(body);

  const canonicalHeaders =
    `content-type:application/json\n` +
    `host:${host}\n` +
    `x-amz-content-sha256:${payloadHash}\n` +
    `x-amz-date:${amzDate}\n`;

  const signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';

  const canonicalRequest = [
    method.toUpperCase(),
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const credentialScope = `${dateStamp}/${credentials.region}/${service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, sha256Hex(canonicalRequest)].join('\n');

  const signingKey = getSignatureKey(credentials.secretAccessKey, dateStamp, credentials.region, service);
  const signature = bytesToHex(hmacSHA256(signingKey, stringToSign));

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    Authorization: authorization,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
  };
}

// =============================================================================// =============================================================================
// Model Definitions
// =============================================================================

export const BEDROCK_MODELS: LLMModel[] = [
  {
    id: 'anthropic.claude-sonnet-4-5-20250929-v1:0',
    name: 'Claude Sonnet 4.5',
    description: 'Standard model - Balanced performance and cost, recommended for most tasks',
    tier: 'standard',
    contextWindow: 200000,
    maxOutputTokens: 8192,
    isDefault: true,
  },
  {
    id: 'anthropic.claude-3-5-haiku-20241022-v1:0',
    name: 'Claude 3.5 Haiku',
    description: 'Economy model - Fast and cost-effective for routine tasks',
    tier: 'economy',
    contextWindow: 200000,
    maxOutputTokens: 8192,
    isDefault: false,
  },
  {
    id: 'anthropic.claude-3-opus-20240229-v1:0',
    name: 'Claude 3 Opus',
    description: 'Flagship model - Most capable, best for complex analysis and reasoning',
    tier: 'flagship',
    contextWindow: 200000,
    maxOutputTokens: 4096,
    isDefault: false,
  },
];

// =============================================================================
// Bedrock Provider
// =============================================================================

/**
 * Bedrock API response structure (same as Anthropic)
 */
interface BedrockAPIResponse {
  id: string;
  type: string;
  role: string;
  content: Array<{
    type: string;
    text: string;
  }>;
  model: string;
  stop_reason: string;
  stop_sequence: string | null;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

/**
 * Bedrock error response structure
 */
interface BedrockErrorResponse {
  message?: string;
  Message?: string;
  type?: string;
  __type?: string;
}

/**
 * AWS Bedrock LLM Provider
 *
 * Provides integration with AWS Bedrock for running Claude models
 * through AWS infrastructure with IAM-based authentication.
 */
export class BedrockProvider implements LLMProvider {
  readonly name = 'AWS Bedrock';
  readonly id = 'bedrock';
  // Endpoint is dynamic (built per-request in callProvider) — placeholder value here
  readonly endpoint = 'https://bedrock-runtime.us-east-1.amazonaws.com';
  readonly keyPrefix = '';
  readonly keyPlaceholder = 'Enter AWS credentials below';
  readonly models: LLMModel[] = BEDROCK_MODELS;

  /**
   * Format a request for the Bedrock Claude invoke API.
   * Same as Anthropic messages format but:
   * - No `model` field (model is in the URL)
   * - Uses `anthropic_version` in body instead of header
   */
  formatRequest(config: RequestConfig): Record<string, unknown> {
    const request: Record<string, unknown> = {
      anthropic_version: 'bedrock-2023-05-31',
      messages: [
        {
          role: 'user',
          content: config.prompt.trim(),
        },
      ],
      max_tokens: config.maxTokens,
    };

    if (config.temperature !== undefined) {
      request.temperature = config.temperature;
    }

    if (config.additionalParams) {
      Object.assign(request, config.additionalParams);
    }

    return request;
  }

  /**
   * Parse Bedrock API response (same structure as Anthropic)
   */
  parseResponse(response: unknown): LLMResponse {
    const bedrockResponse = response as BedrockAPIResponse;

    if (!bedrockResponse.content || !Array.isArray(bedrockResponse.content)) {
      throw new LLMError(
        'Invalid response format from AWS Bedrock: missing content array',
        LLMErrorCode.INVALID_REQUEST
      );
    }

    const textContent = bedrockResponse.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');

    if (!textContent) {
      throw new LLMError(
        'Invalid response format from AWS Bedrock: no text content found',
        LLMErrorCode.INVALID_REQUEST
      );
    }

    return {
      content: textContent.trim(),
      model: bedrockResponse.model,
      usage: bedrockResponse.usage
        ? {
            promptTokens: bedrockResponse.usage.input_tokens,
            completionTokens: bedrockResponse.usage.output_tokens,
            totalTokens: bedrockResponse.usage.input_tokens + bedrockResponse.usage.output_tokens,
          }
        : undefined,
      metadata: {
        id: bedrockResponse.id,
        stopReason: bedrockResponse.stop_reason,
      },
    };
  }

  /**
   * Validate Bedrock credentials JSON
   */
  validateApiKey(jsonStr: string): ApiKeyValidationResult {
    if (!jsonStr || typeof jsonStr !== 'string' || !jsonStr.trim()) {
      return {
        isValid: false,
        error: 'AWS credentials required. Please enter your Access Key ID, Secret Access Key, and Region.',
      };
    }

    try {
      parseBedrockCredentials(jsonStr);
      return { isValid: true };
    } catch (err) {
      return {
        isValid: false,
        error: `Invalid AWS credentials: ${err instanceof Error ? err.message : 'unknown error'}`,
      };
    }
  }

  /**
   * Get base headers — SigV4 headers are added dynamically in callProvider
   */
  getHeaders(_apiKey: string): RequestHeaders {
    return {
      'content-type': 'application/json',
    };
  }

  /**
   * Get the default model (Claude 3.5 Sonnet)
   */
  getDefaultModel(): LLMModel {
    return this.models.find((m) => m.isDefault) ?? this.models[0];
  }

  /**
   * Handle Bedrock-specific error responses
   */
  handleError(statusCode: number, response: unknown): LLMError {
    const errorResponse = response as BedrockErrorResponse | null;
    const errorMessage =
      errorResponse?.message ||
      errorResponse?.Message ||
      (typeof response === 'string' ? response : 'Unknown error');

    switch (statusCode) {
      case 400:
        return new LLMError(
          `AWS Bedrock Error (400): ${errorMessage}. Please check your request.`,
          LLMErrorCode.INVALID_REQUEST,
          400
        );

      case 401:
      case 403:
        return new LLMError(
          `AWS Bedrock Error (${statusCode}): ${errorMessage}. Check IAM permissions and that the model is enabled in your region.`,
          LLMErrorCode.INVALID_API_KEY,
          statusCode
        );

      case 404:
        return new LLMError(
          `AWS Bedrock Error (404): Model not found. Please verify the model ID and that it is enabled in your AWS region.`,
          LLMErrorCode.MODEL_NOT_FOUND,
          404
        );

      case 429:
        return new LLMError(
          'AWS Bedrock Error (429): Rate limit exceeded. Please try again later.',
          LLMErrorCode.RATE_LIMIT_EXCEEDED,
          429
        );

      case 500:
        return new LLMError(
          'AWS Bedrock Error (500): Server error. Please try again later.',
          LLMErrorCode.SERVER_ERROR,
          500
        );

      case 503:
        return new LLMError(
          'AWS Bedrock Error (503): Service unavailable. Please try again later.',
          LLMErrorCode.SERVICE_UNAVAILABLE,
          503
        );

      default:
        return new LLMError(
          `AWS Bedrock Error (${statusCode}): ${errorMessage}`,
          LLMErrorCode.UNKNOWN_ERROR,
          statusCode
        );
    }
  }
}

/**
 * Singleton instance of the Bedrock provider
 */
export const bedrockProvider = new BedrockProvider();

export default bedrockProvider;
