import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { createHash, timingSafeEqual } from 'crypto';
import { setCorsHeaders } from '@/lib/cors';
import { verifyOtpToken } from '@/lib/otpToken';
import { validateVerifyOtpPayload } from '@/lib/otpValidation';
import { authenticateApiRequest } from '@/lib/apiAuth';
import { consumeSlidingWindowLimit } from '@/lib/rateLimit';
import { enforceOtpRequestAccess } from '@/lib/ipAccessControl';

// Brute-force protection for OTP guessing. A 6-digit OTP has 1,000,000
// combinations; without these caps an attacker could script guesses until the
// OTP expires. The PER-MOBILE limit is the precise guard (each user/OTP gets
// only a few tries). The PER-IP limit is a loose backstop against scripted
// mobile-number rotation; it is set high because many legitimate users share
// one public IP (campus WiFi, carrier NAT). There is intentionally NO IP-wide
// block — one bad actor must not be able to lock out everyone behind the same IP.
const VERIFY_MOBILE_LIMIT = 5; // wrong/total attempts per mobile...
const VERIFY_MOBILE_WINDOW_MS = 10 * 60 * 1000; // ...per 10 minutes.
const VERIFY_IP_LIMIT = 300; // attempts per IP (loose anti-rotation backstop)...
const VERIFY_IP_WINDOW_MS = 10 * 60 * 1000; // ...per 10 minutes.

export async function POST(request: NextRequest) {
  const authResponse = authenticateApiRequest(request);
  if (authResponse) {
    return authResponse;
  }

  const accessDecision = await enforceOtpRequestAccess(request);
  if (!accessDecision.allowed) {
    const response = NextResponse.json(
      {
        status: 'error',
        code: accessDecision.code,
        message: accessDecision.message,
      },
      { status: accessDecision.status }
    );
    setCorsHeaders(response, request);
    return response;
  }

  const payload = await request.json();
  const validation = validateVerifyOtpPayload(payload);

  if (!validation.ok) {
    const response = NextResponse.json(
      { status: 'error', message: validation.message },
      { status: 400 }
    );
    setCorsHeaders(response, request);
    return response;
  }

  const { otp, mobileNumber, token } = validation.data;

  // --- Brute-force guards (run before any OTP comparison) ---
  const clientIpAddress = accessDecision.clientIpAddress;

  const ipLimitResult = await consumeSlidingWindowLimit(
    `otp:verify:ip:${clientIpAddress}`,
    VERIFY_IP_WINDOW_MS,
    VERIFY_IP_LIMIT
  );

  if (!ipLimitResult.allowed) {
    const response = NextResponse.json(
      {
        status: 'error',
        message: 'Too many attempts. Please try again later.',
        retry_after_seconds: ipLimitResult.retryAfterSeconds,
      },
      { status: 429 }
    );
    setCorsHeaders(response, request);
    return response;
  }

  // Per-mobile cap: the tightest guard against guessing a single user's OTP.
  const mobileLimitResult = await consumeSlidingWindowLimit(
    `otp:verify:mobile:${mobileNumber}`,
    VERIFY_MOBILE_WINDOW_MS,
    VERIFY_MOBILE_LIMIT
  );

  if (!mobileLimitResult.allowed) {
    const response = NextResponse.json(
      {
        status: 'error',
        message: 'Too many incorrect attempts. Please request a new OTP.',
        retry_after_seconds: mobileLimitResult.retryAfterSeconds,
      },
      { status: 429 }
    );
    setCorsHeaders(response, request);
    return response;
  }

  // Preferred path: stateless signed token from /send-otp. Works on Safari/iOS
  // and any browser that blocks the third-party cookie used below.
  if (token) {
    const result = verifyOtpToken(token, mobileNumber, otp);

    if (result === 'expired') {
      const response = NextResponse.json(
        { status: 'error', message: 'OTP expired' },
        { status: 400 }
      );
      setCorsHeaders(response, request);
      return response;
    }

    if (result === 'valid') {
      const response = NextResponse.json({
        status: 'success',
        message: 'OTP verified successfully',
      });
      setCorsHeaders(response, request);
      return response;
    }

    const response = NextResponse.json(
      { status: 'error', message: 'Invalid OTP' },
      { status: 400 }
    );
    setCorsHeaders(response, request);
    return response;
  }

  // Legacy fallback: cookie-based verification (browsers that allow the cookie).
  const cookieStore = await cookies();
  const storedOtp = cookieStore.get('otp')?.value;
  const otpTime = cookieStore.get('otpTime')?.value;

  if (!storedOtp) {
    const response = NextResponse.json(
      {
        status: 'error',
        message: 'OTP not found. Please request again.',
      },
      { status: 400 }
    );
    setCorsHeaders(response, request);
    return response;
  }

  if (!otpTime || Date.now() - parseInt(otpTime) > 3 * 60 * 1000) {
    cookieStore.delete('otp');
    cookieStore.delete('otpTime');

    const response = NextResponse.json(
      {
        status: 'error',
        message: 'OTP expired',
      },
      { status: 400 }
    );
    setCorsHeaders(response, request);
    return response;
  }

  const submittedHash = createHash('sha256')
    .update(String(otp ?? ''))
    .digest('hex');
  const storedBuf = Buffer.from(storedOtp, 'hex');
  const submittedBuf = Buffer.from(submittedHash, 'hex');
  const matches =
    storedBuf.length === submittedBuf.length &&
    timingSafeEqual(storedBuf, submittedBuf);

  if (matches) {
    cookieStore.delete('otp');
    cookieStore.delete('otpTime');

    const response = NextResponse.json({
      status: 'success',
      message: 'OTP verified successfully',
    });
    setCorsHeaders(response, request);
    return response;
  }

  const response = NextResponse.json(
    {
      status: 'error',
      message: 'Invalid OTP',
    },
    { status: 400 }
  );
  setCorsHeaders(response, request);
  return response;
}

export async function OPTIONS(request: NextRequest) {
  const response = new NextResponse(null, { status: 200 });
  setCorsHeaders(response, request);
  return response;
}
