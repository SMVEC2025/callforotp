const COLLEGES = ['mailam', 'mvit', 'smvec'] as const;

type College = (typeof COLLEGES)[number];

type ValidationResult<T> =
  | { ok: true; data: T }
  | { ok: false; message: string };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeMobileNumber(value: unknown) {
  const digitsOnly = String(value ?? '').replace(/\D/g, '');
  return /^[6-9]\d{9}$/.test(digitsOnly) ? digitsOnly : null;
}

function normalizeCollege(value: unknown): College | null {
  if (typeof value !== 'string') {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  return COLLEGES.includes(normalized as College) ? (normalized as College) : null;
}

function normalizeOtp(value: unknown) {
  const otp = String(value ?? '').trim();
  return /^\d{6}$/.test(otp) ? otp : null;
}

function normalizeToken(value: unknown) {
  if (typeof value !== 'string') {
    return null;
  }

  const token = value.trim();
  return /^\d+\.[a-f0-9]{64}$/i.test(token) ? token : null;
}

export function validateSendOtpPayload(payload: unknown): ValidationResult<{
  mobileNumber: string;
  college: College;
}> {
  if (!isPlainObject(payload)) {
    return { ok: false, message: 'Request body must be a JSON object.' };
  }

  const mobileNumber = normalizeMobileNumber(payload.mobile_number);
  if (!mobileNumber) {
    return {
      ok: false,
      message: 'Please enter a valid mobile number.',
    };
  }

  const college = normalizeCollege(payload.college);
  if (!college) {
    return { ok: false, message: 'unauthorized' };
  }

  return {
    ok: true,
    data: {
      mobileNumber,
      college,
    },
  };
}

export function validateVerifyOtpPayload(payload: unknown): ValidationResult<{
  otp: string;
  mobileNumber: string;
  token: string | null;
}> {
  if (!isPlainObject(payload)) {
    return { ok: false, message: 'Request body must be a JSON object.' };
  }

  const otp = normalizeOtp(payload.otp);
  if (!otp) {
    return { ok: false, message: 'OTP must be exactly 6 digits.' };
  }

  const token = payload.token == null || payload.token === '' ? null : normalizeToken(payload.token);
  if (payload.token != null && payload.token !== '' && !token) {
    return { ok: false, message: 'Token format is invalid.' };
  }

  // Mobile number is required: it keys the per-mobile brute-force limit and
  // binds the OTP to a specific number in the token flow.
  const mobileNumber = normalizeMobileNumber(payload.mobile_number);
  if (!mobileNumber) {
    return {
      ok: false,
      message: 'Please enter a valid mobile number.',
    };
  }

  return {
    ok: true,
    data: {
      otp,
      mobileNumber,
      token,
    },
  };
}
