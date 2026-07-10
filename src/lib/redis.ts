import { createClient, type RedisClientType } from 'redis';

declare global {
  var __redisClientPromise__: Promise<RedisClientType> | undefined;
}

function getRedisUrl() {
  const redisUrl = process.env.REDIS_URL;

  if (!redisUrl) {
    throw new Error('Missing REDIS_URL environment variable.');
  }

  return redisUrl;
}

async function createRedisClient() {
  const client = createClient({
    url: getRedisUrl(),
  });

  client.on('error', (error) => {
    console.error('Redis client error', error);
  });

  await client.connect();
  return client;
}

export function getRedisClient() {
  if (!globalThis.__redisClientPromise__) {
    globalThis.__redisClientPromise__ = createRedisClient();
  }

  return globalThis.__redisClientPromise__;
}
