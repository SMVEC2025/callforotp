import { isIP } from 'node:net';

const CLIENT_IP_HEADERS = ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip'] as const;

function normalizeIpAddress(candidate: string) {
  let value = candidate.trim();
  if (!value) {
    return null;
  }

  if (value.includes(',')) {
    const [firstValue] = value.split(',');
    value = firstValue?.trim() ?? '';
  }

  if (value.startsWith('[') && value.includes(']')) {
    value = value.slice(1, value.indexOf(']'));
  }

  if (value.startsWith('::ffff:')) {
    const mappedIpv4 = value.slice(7);
    if (isIP(mappedIpv4) === 4) {
      value = mappedIpv4;
    }
  }

  if (isIP(value)) {
    return value;
  }

  const ipv4WithPortMatch = value.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/);
  if (ipv4WithPortMatch?.[1] && isIP(ipv4WithPortMatch[1]) === 4) {
    return ipv4WithPortMatch[1];
  }

  return null;
}

function isPrivateIpv4(ipAddress: string) {
  const octets = ipAddress.split('.').map((segment) => Number(segment));
  if (octets.length !== 4 || octets.some((segment) => Number.isNaN(segment))) {
    return false;
  }

  const [first, second] = octets;

  if (first === 10 || first === 127) {
    return true;
  }

  if (first === 172 && second >= 16 && second <= 31) {
    return true;
  }

  return first === 192 && second === 168;
}

function isPrivateIpv6(ipAddress: string) {
  const normalized = ipAddress.toLowerCase();

  return (
    normalized === '::1' ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    normalized.startsWith('fe80:')
  );
}

export function getClientIpAddress(request: Request) {
  for (const headerName of CLIENT_IP_HEADERS) {
    const headerValue = request.headers.get(headerName);
    if (!headerValue) {
      continue;
    }

    const normalizedIp = normalizeIpAddress(headerValue);
    if (normalizedIp) {
      return normalizedIp;
    }
  }

  return 'unknown';
}

export function isLocalOrPrivateIpAddress(ipAddress: string) {
  const normalizedIp = normalizeIpAddress(ipAddress);
  if (!normalizedIp) {
    return false;
  }

  const ipVersion = isIP(normalizedIp);
  if (ipVersion === 4) {
    return isPrivateIpv4(normalizedIp);
  }

  if (ipVersion === 6) {
    return isPrivateIpv6(normalizedIp);
  }

  return false;
}
