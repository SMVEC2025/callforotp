# OTP Backend API

A Next.js application providing API services for OTP (One-Time Password) generation and verification via SMS.

## Getting Started

First, install dependencies:

```bash
npm install
```

Create a `.env.local` file in the root directory with the following variables:

```
PORT=5000
SMS_API_KEY=your_api_key
SMS_TEMPLATE_ID=your_template_id
SMS_TEMPLATE_ID_MVIT=your_mvit_template_id
SMS_TEMPLATE_ID_MAILAM=your_mailam_template_id
REACT_ORIGIN=http://localhost:3000,http://localhost:3001
SESSION_SECRET=your_secret_key
API_AUTH_KEY=your_internal_api_key
REDIS_URL=redis://localhost:6379
OTP_ALLOWED_COUNTRIES=IN
OTP_IP_LOOKUP_URL_TEMPLATE=https://free.freeipapi.com/api/json/{ip}
```

Replace the placeholder values with your actual SMS API credentials. Add multiple React/frontend origins as a comma-separated list in `REACT_ORIGIN`.

Then, run the development server:

```bash
PORT=5000 npm run dev
```

The API will be available at [http://localhost:5000](http://localhost:5000).

## API Endpoints

## Access Control

- Public OTP requests are allowed only from countries listed in `OTP_ALLOWED_COUNTRIES` (`IN` by default).
- Public IPs identified as proxy or VPN are blocked.
- Once a public IP is blocked for country or proxy reasons, it is stored in Redis and denied on later requests until the key is removed.
- Local development IPs such as `127.0.0.1`, `::1`, and private LAN ranges bypass this check.
- In production, your reverse proxy or platform must forward the real client IP in `x-forwarded-for`, `x-real-ip`, or `cf-connecting-ip`.

### Send OTP

**POST** `/api/send-otp`

Sends an OTP to the provided mobile number via SMS.

**Request Body:**
```json
{
  "mobile_number": "1234567890",
  "college": "mvit"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "OTP sent successfully"
}
```

### Verify OTP

**POST** `/api/verify-otp`

Verifies the provided OTP.

**Request Body:**
```json
{
  "otp": "123456"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "OTP verified successfully"
}
```

## Frontend Integration

Use the following fetch calls from your React frontend:

### Send OTP
```javascript
await fetch("http://localhost:5000/api/send-otp", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ mobile_number: mobile }),
});
```

### Verify OTP
```javascript
await fetch("http://localhost:5000/api/verify-otp", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ otp }),
});
```

## Learn More

- [Next.js Documentation](https://nextjs.org/docs)
- [SMS API Documentation](http://site.ping4sms.com/)
