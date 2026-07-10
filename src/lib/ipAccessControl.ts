import { getRedisClient } from '@/lib/redis';
import { getClientIpAddress, isLocalOrPrivateIpAddress } from '@/lib/clientIp';

type BlockReasonCode = 'country_blocked' | 'proxy_blocked';

type BlockedIpRecord = {
  blockedAt: number;
  countryCode: string | null;
  ipAddress: string;
  reasonCode: BlockReasonCode;
};

type CachedIpLookup = {
  cachedAt: number;
  countryCode: string | null;
  ipAddress: string;
  isProxy: boolean;
};

type OtpAccessDecision =
  | {
      allowed: true;
      clientIpAddress: string;
    }
  | {
      allowed: false;
      clientIpAddress: string;
      code: 'country_blocked' | 'proxy_blocked' | 'ip_lookup_failed' | 'ip_unavailable';
      message: string;
      status: 403 | 503;
    };

const BLOCKED_IP_KEY_PREFIX = 'otp:access:block:ip:';
const LOOKUP_CACHE_KEY_PREFIX = 'otp:access:lookup:ip:';
const DEFAULT_ALLOWED_COUNTRIES = ['IN'];
const DEFAULT_LOOKUP_CACHE_TTL_SECONDS = 24 * 60 * 60;
const DEFAULT_LOOKUP_TIMEOUT_MS = 5000;
const DEFAULT_LOOKUP_URL_TEMPLATE = 'https://free.freeipapi.com/api/json/{ip}';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseBoolean(value: unknown) {
  return value === true;
}

function getAllowedCountryCodes() {
  const configuredCountries = process.env.OTP_ALLOWED_COUNTRIES ?? DEFAULT_ALLOWED_COUNTRIES.join(',');

  return new Set(
    configuredCountries
      .split(',')
      .map((countryCode) => countryCode.trim().toUpperCase())
      .filter(Boolean)
  );
}

function getLookupTimeoutMs() {
  const configuredTimeout = Number(process.env.OTP_IP_LOOKUP_TIMEOUT_MS);

  if (Number.isFinite(configuredTimeout) && configuredTimeout > 0) {
    return configuredTimeout;
  }

  return DEFAULT_LOOKUP_TIMEOUT_MS;
}

function getLookupCacheTtlSeconds() {
  const configuredTtl = Number(process.env.OTP_IP_LOOKUP_CACHE_TTL_SECONDS);

  if (Number.isFinite(configuredTtl) && configuredTtl > 0) {
    return Math.floor(configuredTtl);
  }

  return DEFAULT_LOOKUP_CACHE_TTL_SECONDS;
}

function buildLookupUrl(ipAddress: string) {
  const template = process.env.OTP_IP_LOOKUP_URL_TEMPLATE?.trim() || DEFAULT_LOOKUP_URL_TEMPLATE;

  if (template.includes('{ip}')) {
    return template.replace('{ip}', encodeURIComponent(ipAddress));
  }

  return `${template.replace(/\/+$/, '')}/${encodeURIComponent(ipAddress)}`;
}

function getBlockedIpKey(ipAddress: string) {
  return `${BLOCKED_IP_KEY_PREFIX}${ipAddress}`;
}

function getLookupCacheKey(ipAddress: string) {
  return `${LOOKUP_CACHE_KEY_PREFIX}${ipAddress}`;
}

function getBlockedMessage(reasonCode: BlockReasonCode) {
  if (reasonCode === 'proxy_blocked') {
    return 'VPN or proxy access is not allowed.';
  }

  return 'Access from your country is not allowed.';
}

function parseBlockedRecord(value: string | null) {
  if (!value) {
    return null;
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (!isPlainObject(parsed) || typeof parsed.reasonCode !== 'string') {
      return null;
    }

    const countryCode =
      typeof parsed.countryCode === 'string' ? parsed.countryCode.toUpperCase() : null;

    if (parsed.reasonCode !== 'country_blocked' && parsed.reasonCode !== 'proxy_blocked') {
      return null;
    }

    return {
      blockedAt: typeof parsed.blockedAt === 'number' ? parsed.blockedAt : Date.now(),
      countryCode,
      ipAddress: typeof parsed.ipAddress === 'string' ? parsed.ipAddress : '',
      reasonCode: parsed.reasonCode,
    } satisfies BlockedIpRecord;
  } catch {
    return null;
  }
}

function parseLookupRecord(value: string | null) {
  if (!value) {
    return null;
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (!isPlainObject(parsed)) {
      return null;
    }

    return {
      cachedAt: typeof parsed.cachedAt === 'number' ? parsed.cachedAt : Date.now(),
      countryCode:
        typeof parsed.countryCode === 'string' ? parsed.countryCode.toUpperCase() : null,
      ipAddress: typeof parsed.ipAddress === 'string' ? parsed.ipAddress : '',
      isProxy: parseBoolean(parsed.isProxy),
    } satisfies CachedIpLookup;
  } catch {
    return null;
  }
}

function parseLookupResponse(payload: unknown, ipAddress: string): CachedIpLookup {
  if (!isPlainObject(payload)) {
    throw new Error('Invalid IP lookup response payload.');
  }

  if (payload.success === false) {
    const message =
      typeof payload.message === 'string' ? payload.message : 'IP lookup provider rejected the request.';
    throw new Error(message);
  }

  const countryCodeSource =
    typeof payload.countryCode === 'string'
      ? payload.countryCode
      : typeof payload.country_code === 'string'
        ? payload.country_code
        : null;

  let isProxy = parseBoolean(payload.isProxy);

  if (!isProxy && isPlainObject(payload.security)) {
    isProxy =
      parseBoolean(payload.security.anonymous) ||
      parseBoolean(payload.security.proxy) ||
      parseBoolean(payload.security.vpn) ||
      parseBoolean(payload.security.tor) ||
      parseBoolean(payload.security.hosting);
  }

  return {
    cachedAt: Date.now(),
    countryCode: countryCodeSource ? countryCodeSource.toUpperCase() : null,
    ipAddress,
    isProxy,
  };
}

async function getPermanentBlock(ipAddress: string) {
  const client = await getRedisClient();
  const value = await client.get(getBlockedIpKey(ipAddress));
  return parseBlockedRecord(value);
}

async function blockIpPermanently(
  ipAddress: string,
  reasonCode: BlockReasonCode,
  countryCode: string | null
) {
  const client = await getRedisClient();
  const record: BlockedIpRecord = {
    blockedAt: Date.now(),
    countryCode,
    ipAddress,
    reasonCode,
  };

  await client.set(getBlockedIpKey(ipAddress), JSON.stringify(record));
}

async function getCachedLookup(ipAddress: string) {
  const client = await getRedisClient();
  const value = await client.get(getLookupCacheKey(ipAddress));
  return parseLookupRecord(value);
}

async function cacheLookup(ipAddress: string, record: CachedIpLookup) {
  const client = await getRedisClient();

  await client.set(getLookupCacheKey(ipAddress), JSON.stringify(record), {
    EX: getLookupCacheTtlSeconds(),
  });
}

async function lookupIpAddress(ipAddress: string) {
  const cachedLookup = await getCachedLookup(ipAddress);
  if (cachedLookup) {
    return cachedLookup;
  }

  const response = await fetch(buildLookupUrl(ipAddress), {
    cache: 'no-store',
    headers: {
      Accept: 'application/json',
    },
    signal: AbortSignal.timeout(getLookupTimeoutMs()),
  });

  if (!response.ok) {
    throw new Error(`IP lookup failed with status ${response.status}.`);
  }

  const payload = (await response.json()) as unknown;
  const record = parseLookupResponse(payload, ipAddress);
  await cacheLookup(ipAddress, record);
  return record;
}

export async function enforceOtpRequestAccess(request: Request): Promise<OtpAccessDecision> {
  const clientIpAddress = getClientIpAddress(request);

  if (clientIpAddress === 'unknown') {
    if (process.env.NODE_ENV !== 'production') {
      return {
        allowed: true,
        clientIpAddress,
      };
    }

    return {
      allowed: false,
      clientIpAddress,
      code: 'ip_unavailable',
      message: 'Unable to determine client IP address.',
      status: 503,
    };
  }

  if (isLocalOrPrivateIpAddress(clientIpAddress)) {
    return {
      allowed: true,
      clientIpAddress,
    };
  }

  const blockedRecord = await getPermanentBlock(clientIpAddress);
  if (blockedRecord) {
    return {
      allowed: false,
      clientIpAddress,
      code: blockedRecord.reasonCode,
      message: getBlockedMessage(blockedRecord.reasonCode),
      status: 403,
    };
  }

  let lookupRecord: CachedIpLookup;

  try {
    lookupRecord = await lookupIpAddress(clientIpAddress);
  } catch (error) {
    console.error('ip access lookup failed', error);

    return {
      allowed: false,
      clientIpAddress,
      code: 'ip_lookup_failed',
      message: 'Unable to verify request origin. Please try again later.',
      status: 503,
    };
  }

  if (lookupRecord.isProxy) {
    await blockIpPermanently(clientIpAddress, 'proxy_blocked', lookupRecord.countryCode);

    return {
      allowed: false,
      clientIpAddress,
      code: 'proxy_blocked',
      message: getBlockedMessage('proxy_blocked'),
      status: 403,
    };
  }

  const allowedCountryCodes = getAllowedCountryCodes();
  if (!lookupRecord.countryCode || !allowedCountryCodes.has(lookupRecord.countryCode)) {
    await blockIpPermanently(clientIpAddress, 'country_blocked', lookupRecord.countryCode);

    return {
      allowed: false,
      clientIpAddress,
      code: 'country_blocked',
      message: getBlockedMessage('country_blocked'),
      status: 403,
    };
  }

  return {
    allowed: true,
    clientIpAddress,
  };
}
