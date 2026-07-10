import { timingSafeEqual } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import { setCorsHeaders } from '@/lib/cors';

const API_KEY_HEADER = 'x-api-key';

function isMatchingApiKey(providedKey: string, expectedKey: string) {
  const providedBuffer = Buffer.from(providedKey);
  const expectedBuffer = Buffer.from(expectedKey);

  return (
    providedBuffer.length === expectedBuffer.length &&
    timingSafeEqual(providedBuffer, expectedBuffer)
  );
}

export function authenticateApiRequest(request: NextRequest) {
  const expectedApiKey = process.env.API_AUTH_KEY;

  if (!expectedApiKey) {
    throw new Error('Missing API_AUTH_KEY environment variable.');
  }

  const providedApiKey = request.headers.get(API_KEY_HEADER);

  if (providedApiKey && isMatchingApiKey(providedApiKey, expectedApiKey)) {
    return null;
  }

  const response = NextResponse.json(
    {
      status: 'error',
      message: 'Unauthorized',
    },
    { status: 401 }
  );

  setCorsHeaders(response, request);

  return response;
}
