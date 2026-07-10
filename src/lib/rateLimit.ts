import { randomUUID } from 'crypto';
import { getRedisClient } from '@/lib/redis';

type RateLimitResult = {
  allowed: boolean;
  retryAfterSeconds: number;
};

const SLIDING_WINDOW_LIMIT_LUA = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local minScore = now - windowMs

redis.call('ZREMRANGEBYSCORE', key, 0, minScore)

local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  if oldest[2] then
    return {0, tonumber(oldest[2])}
  end

  return {0, now}
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, windowMs)

return {1, 0}
`;

export async function consumeSlidingWindowLimit(
  key: string,
  windowMs: number,
  limit: number
): Promise<RateLimitResult> {
  const now = Date.now();
  const client = await getRedisClient();
  const result = (await client.eval(SLIDING_WINDOW_LIMIT_LUA, {
    keys: [key],
    arguments: [String(now), String(windowMs), String(limit), `${now}-${randomUUID()}`],
  })) as [number, number];

  const [allowed, oldestTimestamp] = result;

  if (allowed === 1) {
    return {
      allowed: true,
      retryAfterSeconds: 0,
    };
  }

  const retryAfterMs = Math.max(oldestTimestamp + windowMs - now, 1000);
  return {
    allowed: false,
    retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
  };
}

export async function isBlocked(key: string) {
  const client = await getRedisClient();
  const value = await client.get(key);
  return value === '1';
}

export async function blockKeyForDuration(key: string, ttlMs: number) {
  const client = await getRedisClient();
  await client.set(key, '1', { PX: ttlMs });
}

export async function incrementExpiringCounter(key: string, windowMs: number) {
  const client = await getRedisClient();
  const count = await client.incr(key);

  if (count === 1) {
    await client.pExpire(key, windowMs);
  }

  return count;
}
