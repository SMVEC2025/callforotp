import { NextResponse } from 'next/server';

const DEFAULT_ALLOWED_METHODS = 'POST, OPTIONS';
const DEFAULT_ALLOWED_HEADERS = ['Content-Type', 'x-api-key'];
const ALLOWED_ORIGINS = [
  'http://localhost:5174',
  'http://localhost:5173',
  'https://alumni.mvit.edu.in',
  'https://alumni.mailamengg.ac.in',
  'https://alumni.smvec.ac.in',
  'https://alumni-mvit.pages.dev',
  'https://alumni-mvit-updated.onrender.com',
  'https://alumni-rdpqdbj4k-premkumars-projects-1e0bc630.vercel.app'
];

function getAllowedOrigins() {
  return ALLOWED_ORIGINS;
}

function getAllowedOrigin(request: Request) {
  const requestOrigin = request.headers.get('origin');
  if (!requestOrigin) {
    return null;
  }

  return getAllowedOrigins().includes(requestOrigin) ? requestOrigin : null;
}

export function setCorsHeaders(response: NextResponse, request: Request) {
  const allowedOrigin = getAllowedOrigin(request);
  const requestedHeaders = request.headers.get('access-control-request-headers');

  if (allowedOrigin) {
    response.headers.set('Access-Control-Allow-Origin', allowedOrigin);
  }

  response.headers.set('Vary', 'Origin');
  response.headers.set('Access-Control-Allow-Credentials', 'true');
  response.headers.set('Access-Control-Allow-Methods', DEFAULT_ALLOWED_METHODS);
  response.headers.set(
    'Access-Control-Allow-Headers',
    requestedHeaders?.trim() || DEFAULT_ALLOWED_HEADERS.join(', ')
  );
}
