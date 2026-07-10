import { createHmac, timingSafeEqual } from 'crypto';

const TOKEN_TTL_MS = 3 * 60 * 1000;

// Server-only secret. Falls back to SMS_API_KEY so the feature works without
// extra configuration; both values never reach the client.
function getSecret() {
  const secret = process.env.SESSION_SECRET || process.env.SMS_API_KEY;
  if (!secret) {
    throw new Error('Missing SESSION_SECRET / SMS_API_KEY for OTP signing.');
  }
  return secret;
}

function normalizeMobile(value: unknown) {
  return String(value ?? '').replace(/\D/g, '').slice(0, 10);
}

function sign(mobile: string, otp: string, expiry: number) {
  return createHmac('sha256', getSecret())
    .update(`${normalizeMobile(mobile)}:${otp}:${expiry}`)
    .digest('hex');
}

/**
 * Build a stateless, cookie-free verification token binding the OTP to the
 * mobile number and an expiry. The OTP itself is never exposed — only an HMAC
 * keyed by a server-side secret — so it cannot be brute-forced from the token.
 */
export function createOtpToken(mobile: string, otp: string | number) {
  const expiry = Date.now() + TOKEN_TTL_MS;
  const signature = sign(mobile, String(otp), expiry);
  return `${expiry}.${signature}`;
}

type VerifyResult = 'valid' | 'expired' | 'invalid';

/**
 * Validate an OTP against a token produced by {@link createOtpToken}.
 * Returns 'expired' when the token's TTL has passed, 'invalid' on any
 * signature mismatch or malformed token, and 'valid' on success.
 */
export function verifyOtpToken(
  token: unknown,
  mobile: unknown,
  otp: unknown
): VerifyResult {
  if (typeof token !== 'string') return 'invalid';

  const separatorIndex = token.indexOf('.');
  if (separatorIndex <= 0) return 'invalid';

  const expiry = Number(token.slice(0, separatorIndex));
  const signature = token.slice(separatorIndex + 1);
  if (!Number.isFinite(expiry) || !signature) return 'invalid';

  if (Date.now() > expiry) return 'expired';

  const expected = sign(String(mobile ?? ''), String(otp ?? ''), expiry);
  const expectedBuf = Buffer.from(expected, 'hex');
  const signatureBuf = Buffer.from(signature, 'hex');
  const matches =
    expectedBuf.length === signatureBuf.length &&
    timingSafeEqual(expectedBuf, signatureBuf);

  return matches ? 'valid' : 'invalid';
}
