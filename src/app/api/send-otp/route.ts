import { NextRequest, NextResponse } from 'next/server';
import axios from 'axios';
import { cookies } from 'next/headers';
import { createHash } from 'crypto';
import { setCorsHeaders } from '@/lib/cors';
import { createOtpToken } from '@/lib/otpToken';
import { validateSendOtpPayload } from '@/lib/otpValidation';
import { consumeSlidingWindowLimit } from '@/lib/rateLimit';
import { authenticateApiRequest } from '@/lib/apiAuth';

const OTP_RESEND_COOLDOWN_MS = 30 * 1000;
const OTP_DAILY_LIMIT = 10;
const OTP_DAILY_WINDOW_MS = 24 * 60 * 60 * 1000;
// IP limits are only a loose backstop against scripted floods. Real abuse
// control is per-mobile (cooldown + daily limit), because many legitimate
// users share one public IP (campus WiFi, mobile carrier NAT). These caps are
// set high enough that a shared network of real users never trips them, and
// there is intentionally NO IP-wide block — one bad actor must not be able to
// lock out everyone behind the same IP.
const IP_LIMITS = [
  { maxRequests: 100, windowMs: 60 * 1000, message: 'Too many requests. Please try again shortly.' },
  { maxRequests: 1000, windowMs: 60 * 60 * 1000, message: 'Too many requests. Please try again shortly.' },
] as const;

const OTP_COOKIE_OPTIONS = {
  maxAge: 3 * 60,
  httpOnly: true,
  secure: true,
  sameSite: 'none' as const,
  path: '/',
};

function getClientIpAddress(request: NextRequest) {
  const forwardedFor = request.headers.get('x-forwarded-for');
  if (forwardedFor) {
    const [firstIp] = forwardedFor.split(',');
    if (firstIp?.trim()) {
      return firstIp.trim();
    }
  }

  const realIp = request.headers.get('x-real-ip');
  if (realIp?.trim()) {
    return realIp.trim();
  }

  const cfConnectingIp = request.headers.get('cf-connecting-ip');
  if (cfConnectingIp?.trim()) {
    return cfConnectingIp.trim();
  }

  return 'unknown';
}

export async function POST(request: NextRequest) {
  try {
    const authResponse = authenticateApiRequest(request);
    if (authResponse) {
      return authResponse;
    }

    let payload: unknown;

    try {
      payload = await request.json();
    } catch {
      const response = NextResponse.json(
        {
          status: 'error',
          message: 'Invalid JSON request body.',
        },
        { status: 400 }
      );

      setCorsHeaders(response, request);

      return response;
    }

    const validation = validateSendOtpPayload(payload);

    if (!validation.ok) {
      const response = NextResponse.json(
        {
          status: 'error',
          message: validation.message,
        },
        { status: 400 }
      );

      setCorsHeaders(response, request);

      return response;
    }

    const { mobileNumber, college } = validation.data;

    const clientIpAddress = getClientIpAddress(request);

    for (const limit of IP_LIMITS) {
      const ipLimitResult = await consumeSlidingWindowLimit(
        `otp:send:ip:${clientIpAddress}`,
        limit.windowMs,
        limit.maxRequests
      );

      if (!ipLimitResult.allowed) {
        const response = NextResponse.json(
          {
            status: 'error',
            message: limit.message,
            retry_after_seconds: ipLimitResult.retryAfterSeconds,
          },
          { status: 429 }
        );

        setCorsHeaders(response, request);

        return response;
      }
    }

    const dailyMobileLimitResult = await consumeSlidingWindowLimit(
      `otp:send:mobile:daily:${mobileNumber}`,
      OTP_DAILY_WINDOW_MS,
      OTP_DAILY_LIMIT
    );

    if (!dailyMobileLimitResult.allowed) {
      const response = NextResponse.json(
        {
          status: 'error',
          message: 'OTP limit reached Pls try after 24hrs',
          retry_after_seconds: dailyMobileLimitResult.retryAfterSeconds,
        },
        { status: 429 }
      );

      setCorsHeaders(response, request);

      return response;
    }

    const mobileCooldownResult = await consumeSlidingWindowLimit(
      `otp:send:mobile:cooldown:${mobileNumber}`,
      OTP_RESEND_COOLDOWN_MS,
      1
    );

    if (!mobileCooldownResult.allowed) {
      const response = NextResponse.json(
        {
          status: 'error',
          message: 'pls try after 1 min',
          retry_after_seconds: mobileCooldownResult.retryAfterSeconds,
        },
        { status: 429 }
      );

      setCorsHeaders(response, request);

      return response;
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    const otpHash = createHash('sha256').update(otp.toString()).digest('hex');

    const cookieStore = await cookies();
    cookieStore.set('otp', otpHash, OTP_COOKIE_OPTIONS);
    cookieStore.set('otpTime', Date.now().toString(), OTP_COOKIE_OPTIONS);

    let msg: string;
    let sender: string;
    let templateId: string;

    switch (college) {
      case 'mailam':
        msg = `${otp} is Your OTP, Mailam Engineering College, Mailam, Villupuram.`;
        sender = 'MECENG';
        templateId = process.env.SMS_TEMPLATE_ID_MAILAM!;
        break;
      case 'mvit':
        msg = `${otp} is Your OTP, Manakula Vinayagar Institute of Technology, Puducherry.`;
        sender = 'MITENG';
        templateId = process.env.SMS_TEMPLATE_ID_MVIT || process.env.SMS_TEMPLATE_ID!;
        break;
      case 'smvec':
        msg = `${otp} is Your OTP, Sri Manakula Vinayagar Engineering College, Puducherry.`;
        sender = 'SMVENG';
        templateId = process.env.SMS_TEMPLATE_ID_SMVEC!;
        break;
      default:
        return NextResponse.json(
          {
            status: 'error',
            message: 'Invalid college. Must be one of: mailam, mvit, smvec',
          },
          { status: 400 }
        );
    }

    const params = new URLSearchParams({
      key: process.env.SMS_API_KEY!,
      route: '4',
      sender,
      number: mobileNumber,
      sms: msg,
      templateid: templateId,
    });

    await axios.post('http://site.ping4sms.com/api/smsapi', params);

    // Stateless, cookie-free token so verification works on browsers that block
    // third-party cookies (Safari/iOS). The cookies above remain as a fallback.
    const token = createOtpToken(mobileNumber, otp);

    const response = NextResponse.json({
      status: 'success',
      message: 'OTP sent successfully',
      token,
    });

    setCorsHeaders(response, request);

    return response;
  } catch (error) {
    console.error('send-otp failed', error);

    const response = NextResponse.json(
      {
        status: 'error',
        message: 'Failed to send OTP',
      },
      { status: 500 }
    );

    setCorsHeaders(response, request);

    return response;
  }
}

export async function OPTIONS(request: NextRequest) {
  const response = new NextResponse(null, { status: 200 });
  setCorsHeaders(response, request);
  return response;
}
