/**
 * 오늘(Onle) 문의 폼 중계 Worker
 *
 * 브라우저 → (Turnstile 토큰 + 문의 내용) → 이 Worker → FormSubmit → onle0803@gmail.com
 *
 * 하는 일
 *  1. 허용된 출처(company.onle.kr)에서 온 요청만 받음 (CORS)
 *  2. IP당 1분 3건 · 1시간 10건 제한 (Durable Object로 정확히 카운트)
 *  3. Cloudflare Turnstile 토큰을 서버에서 검증 (봇·매크로 차단)
 *  4. 입력값 검증·정리 후 FormSubmit으로 전달
 */

const TURNSTILE_VERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

// [허용 건수, 기간(ms)]
const RATE_LIMITS = [
  [3, 60 * 1000],        // 1분에 3건
  [10, 60 * 60 * 1000],  // 1시간에 10건
];

const LIMITS = { name: 40, phone: 20, email: 120, message: 2000, type: 20 };

// 제어문자(개행·탭 제외) 제거용
const CONTROL_CHARS = new RegExp('[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]', 'g');

/* ---------- IP별 속도 제한 Durable Object ---------- */
export class RateLimiter {
  constructor(state) {
    this.state = state;
    this.hits = []; // 타임스탬프 목록 (IP 하나당 객체 하나)
  }
  async fetch(request) {
    const { limits, dry } = await request.json();
    const now = Date.now();
    const longest = Math.max(...limits.map((l) => l[1]));
    this.hits = this.hits.filter((t) => now - t < longest);

    let allowed = true;
    let retryAfter = 0;
    for (const [limit, windowMs] of limits) {
      const inWindow = this.hits.filter((t) => now - t < windowMs);
      if (inWindow.length >= limit) {
        allowed = false;
        retryAfter = Math.max(retryAfter, Math.ceil((inWindow[0] + windowMs - now) / 1000));
      }
    }
    if (allowed && !dry) this.hits.push(now);
    return Response.json({ allowed, retryAfter });
  }
}

/* ---------- 유틸 ---------- */
function allowedOrigins(env) {
  return (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function corsHeaders(origin, env) {
  const allowed = allowedOrigins(env);
  const ok = allowed.includes(origin);
  return {
    'Access-Control-Allow-Origin': ok ? origin : allowed[0] || '',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

function json(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers },
  });
}

function clean(v, max) {
  return String(v == null ? '' : v).replace(CONTROL_CHARS, '').trim().slice(0, max);
}

async function checkRate(env, ip, dry) {
  if (!env.LIMITER) return { allowed: true, retryAfter: 0, limiter: 'missing' };
  const stub = env.LIMITER.get(env.LIMITER.idFromName('ip:' + ip));
  const r = await stub.fetch('https://limiter/check', {
    method: 'POST',
    body: JSON.stringify({ limits: RATE_LIMITS, dry: !!dry }),
  }).then((res) => res.json()).catch(() => ({ allowed: true, retryAfter: 0 }));
  return { ...r, limiter: 'ok' };
}

/* ---------- 메인 ---------- */
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin, env);
    const allowed = allowedOrigins(env);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    if (request.method === 'GET' && new URL(request.url).pathname === '/health') {
      // 상태 확인용 (비밀값 노출 없음, 카운트 소모 없음)
      const r = await checkRate(env, ip, true);
      return json({ ok: true, rateLimiter: r.limiter, allowedNow: r.allowed, turnstileSecret: env.TURNSTILE_SECRET ? 'set' : 'missing' }, 200, cors);
    }

    if (request.method !== 'POST') return json({ ok: false, error: 'method' }, 405, cors);

    // 1) 출처 확인
    if (!allowed.includes(origin)) return json({ ok: false, error: 'origin' }, 403, cors);

    // 2) IP 기준 속도 제한
    const rate = await checkRate(env, ip, false);
    if (!rate.allowed) {
      return json(
        { ok: false, error: 'rate', message: '문의가 너무 자주 접수되었습니다. ' + (rate.retryAfter >= 60 ? Math.ceil(rate.retryAfter / 60) + '분' : rate.retryAfter + '초') + ' 뒤 다시 시도해주세요.' },
        429,
        { ...cors, 'Retry-After': String(rate.retryAfter || 60) },
      );
    }

    // 3) 본문 파싱
    let body;
    try { body = await request.json(); } catch { return json({ ok: false, error: 'body' }, 400, cors); }

    const token = clean(body.token, 4096);
    const type = clean(body.type, LIMITS.type);
    const name = clean(body.name, LIMITS.name);
    const phone = clean(body.phone, LIMITS.phone);
    const email = clean(body.email, LIMITS.email);
    const message = clean(body.message, LIMITS.message);
    const honey = clean(body.website, 100); // 허니팟

    if (honey) return json({ ok: true }, 200, cors); // 봇: 성공한 척 무시
    if (!token) return json({ ok: false, error: 'captcha', message: '보안 확인을 완료해주세요.' }, 400, cors);
    if (!name || !phone || !message) return json({ ok: false, error: 'fields', message: '이름, 연락처, 문의 내용을 입력해주세요.' }, 400, cors);
    if (phone.replace(/\D/g, '').length < 9) return json({ ok: false, error: 'phone', message: '연락처를 정확히 입력해주세요.' }, 400, cors);
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ ok: false, error: 'email', message: '이메일 형식을 확인해주세요.' }, 400, cors);

    // 4) Turnstile 검증
    const verify = await fetch(TURNSTILE_VERIFY, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip }),
    }).then((r) => r.json()).catch(() => ({ success: false }));
    if (!verify.success) return json({ ok: false, error: 'captcha', message: '보안 확인에 실패했습니다. 새로고침 후 다시 시도해주세요.' }, 400, cors);

    // 5) FormSubmit으로 전달
    const payload = {
      _subject: `[오늘] ${type || '문의'} - ${name}`,
      _template: 'table',
      _captcha: 'false',
      '문의구분': type || '(미선택)',
      '이름': name,
      '연락처': phone,
      '이메일': email || '(미입력)',
      '문의내용': message,
      'IP': ip,
    };
    if (email) payload._replyto = email;

    const fs = await fetch(`https://formsubmit.co/ajax/${env.TO_EMAIL}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Origin': allowed[0],
        'Referer': allowed[0] + '/',
      },
      body: JSON.stringify(payload),
    }).then((r) => r.json()).catch(() => null);

    if (!fs || String(fs.success) !== 'true') {
      return json({ ok: false, error: 'deliver', message: '전송에 실패했습니다. 잠시 후 다시 시도해주세요.' }, 502, cors);
    }
    return json({ ok: true }, 200, cors);
  },
};
