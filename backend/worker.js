/**
 * GgooAt 后端 v2（Cloudflare Worker + KV）
 * ------------------------------------------------------------------
 * 公开：
 *   GET  /api/health
 *   POST /api/redeem   {code}                     兑换（可带 Bearer 登录态）
 * 用户：
 *   POST /api/auth/register {username,password}   注册（送初始次数）
 *   POST /api/auth/login    {username,password}   登录 → token + 档案
 *   POST /api/auth/logout   {token}               退出
 *   POST /api/user/me                             拉取档案（Bearer）
 *   POST /api/user/spend                          消耗 1 次（Bearer）
 *   POST /api/user/setcredits {credits}           设置次数（Bearer）
 *   POST /api/user/sync {profile?,history?}       同步昵称/头像/历史（Bearer）
 * 管理员（账号密码登录，会话 7 天）：
 *   POST /api/admin/login   {user,pass}
 *   POST /api/admin/list | save | delete | reset | logs
 *   POST /api/admin/users                          查看全部用户
 *   POST /api/admin/setuser {username,credits}     设置某用户次数
 *
 * 环境绑定：CODES(KV)、ADMIN_USER(secret)、ADMIN_PASS(secret)
 * 支付：alipay.js（支付宝配置取 ALIPAY_* 环境变量；订单存 KV order: 前缀）
 */

import { loadAlipayConfig, buildPagePayForm, verifyNotifySign, alipayGatewayRequest, mapTradeStatus, normalizeAmountText } from './alipay.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Token',
  'Access-Control-Max-Age': '86400',
};

const KEY_CODES = 'codes';
const KEY_LOGS = 'logs';
const INITIAL_CREDITS = 5;
const SESSION_TTL_USER = 60 * 60 * 24 * 30;   // 30 天
const SESSION_TTL_ADMIN = 60 * 60 * 24 * 7;   // 7 天
const HISTORY_LIMIT = 20;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

async function readBody(request) {
  try { return await request.json(); } catch (e) { return {}; }
}

function normName(s) { return String(s == null ? '' : s).trim(); }
function normCode(code) { return String(code == null ? '' : code).trim().toUpperCase(); }

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// PBKDF2-SHA256 加盐哈希（1 万次迭代，Worker 免费版 CPU 限制内）
async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 10000 },
    key, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function userKey(name) { return 'user:' + normName(name).toLowerCase(); }

async function loadUser(env, name) {
  const raw = await env.CODES.get(userKey(name));
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

async function saveUser(env, user) {
  await env.CODES.put(userKey(user.username), JSON.stringify(user));
}

function publicProfile(user) {
  return {
    username: user.username,
    nickname: user.profile ? user.profile.nickname : user.username,
    avatar: user.profile ? (user.profile.avatar || '') : '',
    credits: user.credits,
    history: Array.isArray(user.history) ? user.history : [],
    membership: memberInfo(user),
    dailyCap: dailyCapOf(user),
    dailyRemaining: dailyRemainingOf(user),
  };
}

// ---------- 会员与每日使用额度模型 ----------
// 每日额度：非会员 10/天；天卡 40/天；周卡 30/天；月卡 20/天；买断 50/天（无时间限制）
// 会员有效期内使用不扣次数余额；非会员每次消耗 1 次数（余额来自次数包/兑换码）
const DAILY_CAPS = { day: 40, week: 30, month: 20, lifetime: 50, free: 10 };

function cnDate() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
}
function isMemberActive(user) {
  if (user.lifetime) return true;
  if (!user.membershipType || !user.membershipExpiry) return false;
  const t = new Date(user.membershipExpiry).getTime();
  return !isNaN(t) && t > Date.now();
}
function dailyCapOf(user) {
  if (user.lifetime) return DAILY_CAPS.lifetime;
  if (isMemberActive(user)) return DAILY_CAPS[user.membershipType] || DAILY_CAPS.free;
  return DAILY_CAPS.free;
}
function dailyUsedOf(user) {
  return user.usageDate === cnDate() ? (parseInt(user.usageCount, 10) || 0) : 0;
}
function dailyRemainingOf(user) {
  return Math.max(0, dailyCapOf(user) - dailyUsedOf(user));
}
function memberInfo(user) {
  const active = isMemberActive(user);
  return {
    active: active,
    lifetime: !!user.lifetime,
    type: active ? (user.lifetime ? 'forever' : user.membershipType) : '',
    expiry: user.membershipExpiry || '',
    cap: dailyCapOf(user),
  };
}

// ---------- 无状态会话令牌（HMAC 签名，避免 KV 读写传播延迟） ----------
function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  bytes.forEach(b => bin += String.fromCharCode(b));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function hmacHex(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createSession(env, name, role, ttlSeconds) {
  const payload = { u: name, role: role, exp: Date.now() + ttlSeconds * 1000 };
  const body = b64urlEncode(JSON.stringify(payload));
  const sig = await hmacHex(body, env.SESSION_SECRET);
  return 'v2.' + body + '.' + sig;
}

// 注册会话票据（邮箱验证通过后 10 分钟内有效，用于完成注册）
async function createPending(env, email) {
  const payload = b64urlEncode(JSON.stringify({ e: email, t: 'reg', exp: Date.now() + 10 * 60 * 1000 }));
  const sig = await hmacHex(payload, env.SESSION_SECRET);
  return 'p2.' + payload + '.' + sig;
}
async function getPending(env, token) {
  if (!token || !env.SESSION_SECRET || !token.startsWith('p2.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const expected = await hmacHex(parts[1], env.SESSION_SECRET);
  if (expected !== parts[2]) return null;
  try {
    const payload = JSON.parse(b64urlDecode(parts[1]));
    if (payload.t !== 'reg' || !payload.exp || payload.exp < Date.now()) return null;
    return String(payload.e || '').toLowerCase();
  } catch (e) { return null; }
}

async function getSession(env, request) {
  const auth = request.headers.get('Authorization') || request.headers.get('X-Admin-Token') || '';
  const token = auth.replace(/^(Bearer\s+)/i, '').trim();
  if (!token || !env.SESSION_SECRET || !token.startsWith('v2.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const expected = await hmacHex(parts[1], env.SESSION_SECRET);
  if (expected !== parts[2]) return null;
  try {
    const payload = JSON.parse(b64urlDecode(parts[1]));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return { role: payload.role, username: payload.u };
  } catch (e) { return null; }
}

async function requireUser(env, request) {
  const s = await getSession(env, request);
  if (!s || s.role !== 'user') return null;
  const user = await loadUser(env, s.username);
  if (!user) return null;
  return { session: s, user: user };
}

async function isAdminSession(env, request) {
  const s = await getSession(env, request);
  return !!(s && s.role === 'admin');
}

async function loadCodes(env) {
  const raw = await env.CODES.get(KEY_CODES);
  if (!raw) return [];
  try { const a = JSON.parse(raw); return Array.isArray(a) ? a : []; } catch (e) { return []; }
}
async function saveCodes(env, list) { await env.CODES.put(KEY_CODES, JSON.stringify(list)); }

async function loadLogs(env) {
  const raw = await env.CODES.get(KEY_LOGS);
  if (!raw) return [];
  try { const a = JSON.parse(raw); return Array.isArray(a) ? a : []; } catch (e) { return []; }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    // ---------- 健康检查 ----------
    if (path === '/api/health' || path === '/') {
      const codes = await loadCodes(env);
      return json({ ok: true, service: 'ggooat-api', version: 2, codes: codes.length });
    }

    // ---------- 注册 ----------
    if (path === '/api/auth/register' && request.method === 'POST') {
      const body = await readBody(request);
      const username = normName(body.username);
      const password = String(body.password == null ? '' : body.password);

      if (username.indexOf('@') !== -1) {
        // 邮箱作为账号
        if (!/^[A-Za-z0-9._%+-]{1,32}@[A-Za-z0-9.-]{1,32}\.[A-Za-z]{2,8}$/.test(username) || username.length > 48) {
          return json({ ok: false, msg: '邮箱格式不正确' });
        }
      } else if (!/^[a-zA-Z0-9_\u4e00-\u9fa5]{2,16}$/.test(username)) {
        return json({ ok: false, msg: '账号需 2-16 位，中英文/数字/下划线' });
      }
      if (password.length < 6 || password.length > 32) {
        return json({ ok: false, msg: '密码需 6-32 位' });
      }
      if (await loadUser(env, username)) {
        return json({ ok: false, msg: '该账号已被注册' });
      }

      // 简单防刷：同一 IP 每天最多注册 10 个
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const day = new Date().toISOString().slice(0, 10);
      const rlKey = 'rl:' + ip + ':' + day;
      const count = parseInt(await env.CODES.get(rlKey), 10) || 0;
      if (count >= 10) return json({ ok: false, msg: '注册过于频繁，请明天再试' });
      await env.CODES.put(rlKey, String(count + 1), { expirationTtl: 86400 });

      const salt = randomHex(16);
      const user = {
        username: username,
        salt: salt,
        hash: await hashPassword(password, salt),
        credits: INITIAL_CREDITS,
        profile: { nickname: username, avatar: '' },
        history: [],
        createdAt: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
        lastSeen: '',
      };
      await saveUser(env, user);
      const token = await createSession(env, username, 'user', SESSION_TTL_USER);
      return json({ ok: true, token: token, profile: publicProfile(user), msg: '注册成功' });
    }

    // ---------- 登录 ----------
    if (path === '/api/auth/login' && request.method === 'POST') {
      const body = await readBody(request);
      const username = normName(body.username);
      const password = String(body.password == null ? '' : body.password);
      const user = await loadUser(env, username);
      if (!user) return json({ ok: false, msg: '账号或密码错误' });

      const hash = await hashPassword(password, user.salt);
      if (hash !== user.hash) return json({ ok: false, msg: '账号或密码错误' });

      user.lastSeen = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
      await saveUser(env, user);
      const token = await createSession(env, username, 'user', SESSION_TTL_USER);
      return json({ ok: true, token: token, profile: publicProfile(user) });
    }

    // ---------- 退出（无状态令牌，客户端删除即可） ----------
    if (path === '/api/auth/logout' && request.method === 'POST') {
      return json({ ok: true });
    }

    // ---------- 邮箱验证码登录/注册第一步（前端先向 Supabase 校验验证码，这里校验其票据） ----------
    if (path === '/api/auth/email-login' && request.method === 'POST') {
      const body = await readBody(request);
      const at = String(body.access_token == null ? '' : body.access_token);
      if (!at || at.length > 4096) return json({ ok: false, msg: '登录票据无效' });

      // 向 Supabase 换取真实用户信息（防止伪造票据）
      let email = '';
      try {
        const r = await fetch(env.SUPABASE_URL + '/auth/v1/user', {
          headers: { 'Authorization': 'Bearer ' + at, 'apikey': env.SUPABASE_ANON_KEY }
        });
        if (!r.ok) return json({ ok: false, msg: '登录校验失败，请重试' });
        const u = await r.json();
        if (!u || !u.email) return json({ ok: false, msg: '登录校验失败' });
        email = String(u.email).toLowerCase();
      } catch (e) {
        return json({ ok: false, msg: '登录校验失败，请重试' });
      }

      // 已有账号：直接登录（邮箱即账号的旧账号，或邮箱绑定的账号）
      let user = await loadUser(env, email);
      if (!user) {
        const bound = await env.CODES.get('email:' + email);
        if (bound) user = await loadUser(env, bound);
      }
      if (user) {
        user.lastSeen = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
        await saveUser(env, user);
        const token = await createSession(env, user.username, 'user', SESSION_TTL_USER);
        return json({ ok: true, token: token, profile: publicProfile(user), msg: '欢迎回来' });
      }

      // 新邮箱：不直接建号，发注册会话票据，让用户设置用户名和密码
      return json({
        ok: false,
        pending: true,
        pending_token: await createPending(env, email),
        email: email,
        msg: '邮箱验证成功，请设置用户名和密码完成注册'
      });
    }

    // ---------- 邮箱注册第二步（设置用户名 + 密码） ----------
    if (path === '/api/auth/email-register' && request.method === 'POST') {
      const body = await readBody(request);
      const email = await getPending(env, String(body.pending_token == null ? '' : body.pending_token));
      if (!email) return json({ ok: false, msg: '注册会话已过期，请重新验证邮箱' });

      const username = normName(body.username);
      const password = String(body.password == null ? '' : body.password);
      if (!/^[a-zA-Z0-9_\u4e00-\u9fa5]{2,16}$/.test(username)) {
        return json({ ok: false, msg: '用户名需 2-16 位，中英文/数字/下划线' });
      }
      if (password.length < 6 || password.length > 32) {
        return json({ ok: false, msg: '密码需 6-32 位' });
      }
      // 用户名唯一：不能与任何已有账号（含邮箱账号、兑换码键）冲突
      if (await loadUser(env, username)) {
        return json({ ok: false, msg: '该用户名已被占用' });
      }
      // 该邮箱不能重复绑定
      if (await env.CODES.get('email:' + email)) {
        return json({ ok: false, msg: '该邮箱已绑定账号，请直接登录' });
      }

      const salt = randomHex(16);
      const user = {
        username: username,
        email: email,
        salt: salt,
        hash: await hashPassword(password, salt),
        credits: INITIAL_CREDITS,
        profile: { nickname: username, avatar: '' },
        history: [],
        createdAt: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
        lastSeen: '',
      };
      await saveUser(env, user);
      await env.CODES.put('email:' + email, username);
      const token = await createSession(env, username, 'user', SESSION_TTL_USER);
      return json({ ok: true, token: token, profile: publicProfile(user), msg: '注册成功！欢迎加入' });
    }

    // ---------- 用户接口 ----------
    if (path.startsWith('/api/user/')) {
      const ctx = await requireUser(env, request);
      if (!ctx) return json({ ok: false, msg: '请先登录' }, 401);
      const action = path.slice('/api/user/'.length);

      if (action === 'me') {
        return json({ ok: true, profile: publicProfile(ctx.user) });
      }

      if (action === 'spend') {
        // 每日额度（以东八区日期为界）+ 会员/非会员消耗规则
        const today = cnDate();
        if (ctx.user.usageDate !== today) {
          ctx.user.usageDate = today;
          ctx.user.usageCount = 0;
        }
        const cap = dailyCapOf(ctx.user);
        const used = parseInt(ctx.user.usageCount, 10) || 0;
        if (used >= cap) {
          return json({
            ok: false, dailyCap: cap, remaining: 0,
            membership: memberInfo(ctx.user),
            msg: ctx.user.lifetime ? '今日 50 次已用完，明天再来'
              : isMemberActive(ctx.user) ? '今日会员次数已用完，明天再来'
                : '今日免费额度（10 次）已用完，开通会员每天最多 20-50 次',
          });
        }
        const member = isMemberActive(ctx.user);
        if (!member) {
          if ((parseInt(ctx.user.credits, 10) || 0) < 1) {
            return json({ ok: false, dailyCap: cap, remaining: cap - used, membership: memberInfo(ctx.user), msg: '次数不足，请充值次数包或开通会员' });
          }
          ctx.user.credits = (parseInt(ctx.user.credits, 10) || 0) - 1;
        }
        ctx.user.usageCount = used + 1;
        ctx.user.lastSeen = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
        await saveUser(env, ctx.user);
        return json({
          ok: true,
          credits: ctx.user.credits,
          dailyCap: cap,
          remaining: Math.max(0, cap - (used + 1)),
          membership: memberInfo(ctx.user),
        });
      }

      if (action === 'setcredits') {
        const body = await readBody(request);
        const v = parseInt(body.credits, 10);
        if (isNaN(v) || v < 0) return json({ ok: false, msg: '次数无效' });
        ctx.user.credits = v;
        await saveUser(env, ctx.user);
        return json({ ok: true, credits: v });
      }

      if (action === 'sync') {
        const body = await readBody(request);
        if (body.profile) {
          ctx.user.profile = ctx.user.profile || {};
          if (typeof body.profile.nickname === 'string' && body.profile.nickname.slice(0, 20)) {
            ctx.user.profile.nickname = body.profile.nickname.slice(0, 20);
          }
          if (typeof body.profile.avatar === 'string') {
            ctx.user.profile.avatar = body.profile.avatar.slice(0, 400000); // 头像 base64 上限 ~300KB
          }
        }
        if (Object.prototype.toString.call(body.history) === '[object Array]') {
          ctx.user.history = body.history.slice(0, HISTORY_LIMIT);
        }
        await saveUser(env, ctx.user);
        return json({ ok: true, profile: publicProfile(ctx.user) });
      }

      return json({ ok: false, msg: '未知操作' }, 404);
    }

    // ---------- 兑换 ----------
    if (path === '/api/redeem' && request.method === 'POST') {
      const body = await readBody(request);
      const code = normCode(body.code);
      if (!code) return json({ ok: false, msg: '请输入兑换码' });

      const list = await loadCodes(env);
      const item = list.find((c) => normCode(c.code) === code);
      if (!item) return json({ ok: false, msg: '兑换码无效，请检查后重试' });

      const maxUses = parseInt(item.maxUses, 10) || 0;
      const used = parseInt(item.used, 10) || 0;
      if (maxUses > 0 && used >= maxUses) {
        return json({ ok: false, msg: '该兑换码已被用完' });
      }

      const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
      item.used = used + 1;
      item.lastUsed = now;

      const logs = await loadLogs(env);
      logs.unshift({ code: item.code, time: now, ip: request.headers.get('CF-Connecting-IP') || '-' });
      if (logs.length > 50) logs.length = 50;

      let credits = null;
      const ctx = await requireUser(env, request);
      if (ctx) {
        ctx.user.credits = parseInt(item.count, 10) || 0;
        ctx.user.lastSeen = now;
        await saveUser(env, ctx.user);
        credits = ctx.user.credits;
      }

      await env.CODES.put(KEY_LOGS, JSON.stringify(logs));
      await saveCodes(env, list);

      const remaining = maxUses > 0 ? Math.max(0, maxUses - item.used) : -1;
      return json({ ok: true, count: parseInt(item.count, 10) || 0, credits: credits, remaining: remaining });
    }

    // ---------- 支付（AI 网页应用收款：下单 / 异步通知 / 状态查询） ----------
    // type: pack=次数包(加次数余额) card=会员卡(每日额度+有效期) buyout=买断(永久+每日额度)
    const PAY_PLANS = {
      p2: { type: 'pack', credits: 2, amount: '1.00', name: '体验包 · 2 次' },
      p13: { type: 'pack', credits: 13, amount: '5.00', name: '畅享包 · 13 次' },
      p25: { type: 'pack', credits: 25, amount: '10.00', name: '超值包 · 25 次' },
      day: { type: 'card', card: 'day', days: 1, perDay: 40, amount: '5.88', name: '天卡 · 每天40次 · 1天' },
      week: { type: 'card', card: 'week', days: 7, perDay: 30, amount: '18.88', name: '周卡 · 每天30次 · 7天' },
      month: { type: 'card', card: 'month', days: 30, perDay: 20, amount: '32.88', name: '月卡 · 每天20次 · 30天' },
      forever: { type: 'buyout', perDay: 50, amount: '88.00', name: '买断 · 每天50次 · 永久' },
    };
    const PAY_RETURN_URL = 'https://ggooat.xyz/pay/return.html';

    function orderKey(no) { return 'order:' + normName(no); }
    async function loadOrder(env, no) {
      const raw = await env.CODES.get(orderKey(no));
      if (!raw) return null;
      try { return JSON.parse(raw); } catch (e) { return null; }
    }
    async function saveOrder(env, order) { await env.CODES.put(orderKey(order.outTradeNo), JSON.stringify(order)); }
    function payNow() { return new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }); }

    // 发货幂等：仅未支付订单入账一次（KV 无事务，以状态字段为准）
    async function creditOrderOnce(env, order, tradeNo) {
      if (order.status === 'PAID') return { credited: false, order: order };
      const fresh = await loadOrder(env, order.outTradeNo);
      if (fresh && fresh.status === 'PAID') return { credited: false, order: fresh };
      const target = fresh || order;
      target.status = 'PAID';
      target.tradeNo = tradeNo || target.tradeNo || '';
      target.paidAt = payNow();
      const u = await loadUser(env, target.username);
      if (u) {
        const plan = PAY_PLANS[target.plan] || {};
        if (plan.type === 'card') {
          // 会员卡：从当前有效期（未过期则顺延）起增加天数
          const base = (u.membershipExpiry && new Date(u.membershipExpiry).getTime() > Date.now())
            ? new Date(u.membershipExpiry).getTime() : Date.now();
          u.membershipExpiry = new Date(base + plan.days * 86400000).toISOString();
          u.membershipType = plan.card;
        } else if (plan.type === 'buyout') {
          u.lifetime = true;
        } else {
          u.credits = (parseInt(u.credits, 10) || 0) + parseInt(target.credits, 10);
        }
        u.lastSeen = payNow();
        await saveUser(env, u);
        target.settledCredits = u.credits;
        target.settledMembership = memberInfo(u);
      }
      await saveOrder(env, target);
      return { credited: true, order: target, credits: u ? u.credits : null };
    }

    if (path === '/api/pay/plans' && request.method === 'GET') {
      const cfg = loadAlipayConfig(env);
      const plans = Object.keys(PAY_PLANS).map((k) => ({
        id: k,
        type: PAY_PLANS[k].type,
        credits: PAY_PLANS[k].credits || 0,
        perDay: PAY_PLANS[k].perDay || 0,
        days: PAY_PLANS[k].days || 0,
        amount: PAY_PLANS[k].amount,
        name: PAY_PLANS[k].name,
      }));
      return json({ ok: true, plans: plans, enabled: cfg.ok });
    }

    if (path === '/api/pay/create' && request.method === 'POST') {
      const ctx = await requireUser(env, request);
      if (!ctx) return json({ ok: false, msg: '请先登录' }, 401);
      const body = await readBody(request);
      const plan = PAY_PLANS[normName(body.plan)];
      if (!plan) return json({ ok: false, msg: '无效的充值档位' });

      const cfg = loadAlipayConfig(env);
      if (!cfg.ok) return json({ ok: false, msg: '支付服务未配置，请联系管理员' }, 503);

      const outTradeNo = 'GG' + Date.now().toString(36).toUpperCase() + randomHex(3).toUpperCase();
      const order = {
        outTradeNo: outTradeNo,
        username: ctx.user.username,
        plan: normName(body.plan),
        credits: plan.credits,
        amount: plan.amount,
        subject: 'GgooAt ' + plan.name,
        status: 'CREATED',
        createdAt: payNow(),
      };
      await saveOrder(env, order);

      try {
        const paymentHtml = await buildPagePayForm(cfg, {
          outTradeNo: outTradeNo,
          totalAmount: plan.amount,
          subject: order.subject,
          returnUrl: PAY_RETURN_URL,
        });
        return json({ ok: true, out_trade_no: outTradeNo, paymentHtml: paymentHtml });
      } catch (e) {
        order.status = 'ERROR';
        order.error = String(e.message || e).slice(0, 120);
        await saveOrder(env, order);
        return json({ ok: false, msg: '创建支付订单失败，请稍后重试' }, 502);
      }
    }

    // 支付宝异步通知：POST 表单，验签 → 业务校验 → 幂等入账 → 纯文本 success/fail
    if (path === '/api/pay/notify' && request.method === 'POST') {
      const cfg = loadAlipayConfig(env);
      if (!cfg.ok) return new Response('fail', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

      const params = {};
      try {
        const form = await request.formData();
        for (const [k, v] of form.entries()) params[k] = String(v);
      } catch (e) {
        return new Response('fail', { status: 400, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }

      try {
        if (!verifyNotifySign(params, cfg.alipayPublicKey)) {
          return new Response('fail', { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
        }

        const order = await loadOrder(env, params.out_trade_no);
        const amountOk = normalizeAmountText(order && order.amount) === normalizeAmountText(params.total_amount);
        const sellerOk = !cfg.sellerId || !params.seller_id || params.seller_id === cfg.sellerId;
        if (!order || params.app_id !== cfg.appId || !amountOk || !sellerOk) {
          return new Response('fail', { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
        }

        // 只有付款成功且非退款/关单/分账事件才认定支付成功
        const isPaidEvent = (params.trade_status === 'TRADE_SUCCESS' || params.trade_status === 'TRADE_FINISHED')
          && !params.out_biz_no && !params.gmt_refund && !params.refund_fee;

        if (isPaidEvent) {
          await creditOrderOnce(env, order, params.trade_no);
        } else {
          const fresh = await loadOrder(env, order.outTradeNo);
          if (fresh && fresh.status !== 'PAID') {
            fresh.lastEvent = params.trade_status || '';
            fresh.lastEventAt = payNow();
            await saveOrder(env, fresh);
          }
        }
        return new Response('success', { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      } catch (e) {
        return new Response('fail', { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }
    }

    // 支付状态查询（同步回跳页轮询）：未收到通知时以 alipay.trade.query 补偿
    if (path === '/api/pay/status' && request.method === 'GET') {
      const ctx = await requireUser(env, request);
      if (!ctx) return json({ ok: false, msg: '请先登录' }, 401);
      const url = new URL(request.url);
      const no = normName(url.searchParams.get('no'));
      const order = await loadOrder(env, no);
      if (!order || order.username !== ctx.user.username) return json({ ok: false, msg: '订单不存在' }, 404);

      if (order.status === 'PAID') {
        const u = await loadUser(env, order.username);
        return json({ ok: true, status: 'PAID', credits: u ? u.credits : null, membership: u ? memberInfo(u) : null, amount: order.amount, plan: order.plan });
      }

      const cfg = loadAlipayConfig(env);
      if (!cfg.ok) return json({ ok: true, status: 'PENDING', msg: '支付服务未配置' });

      const r = await alipayGatewayRequest(cfg, 'alipay.trade.query', { out_trade_no: no });
      if (r.code === '10000') {
        const state = mapTradeStatus(r.trade_status);
        if (state === 'PAID') {
          const res = await creditOrderOnce(env, order, r.trade_no);
          const u = await loadUser(env, order.username);
          return json({ ok: true, status: 'PAID', credits: u ? u.credits : null, membership: u ? memberInfo(u) : null, amount: order.amount, plan: order.plan });
        }
        return json({ ok: true, status: state });
      }
      if (r.subCode === 'ACQ.TRADE_NOT_EXIST') return json({ ok: true, status: 'PENDING' });
      return json({ ok: true, status: 'UNKNOWN', msg: r.msg + ' ' + (r.subMsg || '') });
    }

    // 管理端：订单列表 / 退款 / 退款查询 / 关闭交易
    if (path === '/api/admin/payorders' && request.method === 'POST') {
      if (!(await isAdminSession(env, request))) return json({ ok: false, msg: '请先登录后台' }, 401);
      let cursor = '';
      const orders = [];
      do {
        const page = await env.CODES.list({ prefix: 'order:', cursor: cursor });
        for (const k of page.keys) {
          const o = await env.CODES.get(k.name);
          if (!o) continue;
          try { orders.push(JSON.parse(o)); } catch (e) { /* 跳过 */ }
        }
        cursor = page.list_complete ? '' : page.cursor;
      } while (cursor);
      orders.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
      const slim = orders.slice(0, 100).map((o) => ({
        outTradeNo: o.outTradeNo, username: o.username, plan: o.plan, credits: o.credits,
        amount: o.amount, status: o.status, createdAt: o.createdAt, paidAt: o.paidAt || '',
        tradeNo: o.tradeNo || '',
      }));
      return json({ ok: true, orders: slim });
    }

    if (path === '/api/admin/payrefund' && request.method === 'POST') {
      if (!(await isAdminSession(env, request))) return json({ ok: false, msg: '请先登录后台' }, 401);
      const body = await readBody(request);
      const no = normName(body.no);
      const cfg = loadAlipayConfig(env);
      if (!cfg.ok) return json({ ok: false, msg: '支付服务未配置' }, 503);
      const order = await loadOrder(env, no);
      if (!order) return json({ ok: false, msg: '订单不存在' });
      const amount = normalizeAmountText(body.amount) || order.amount;
      const outRequestNo = normName(body.out_request_no) || (no + 'R' + ((parseInt(order.refundSeq, 10) || 0) + 1));
      const r = await alipayGatewayRequest(cfg, 'alipay.trade.refund', {
        out_trade_no: no,
        refund_amount: amount,
        out_request_no: outRequestNo,
        refund_reason: normName(body.reason || '管理员退款'),
      });
      if (r.code !== '10000') return json({ ok: false, msg: '退款失败：' + (r.subMsg || r.msg) });
      order.refund = order.refund || [];
      order.refund.push({ outRequestNo: outRequestNo, amount: amount, fundChange: r.fund_change || '', at: payNow() });
      order.refundSeq = (parseInt(order.refundSeq, 10) || 0) + 1;
      await saveOrder(env, order);
      return json({
        ok: r.fund_change === 'Y',
        fundChange: r.fund_change || '',
        msg: r.fund_change === 'Y' ? '退款成功' : '退款受理成功但资金未确认，请稍后用退款查询确认',
        out_request_no: outRequestNo,
      });
    }

    if (path === '/api/admin/payrefundquery' && request.method === 'POST') {
      if (!(await isAdminSession(env, request))) return json({ ok: false, msg: '请先登录后台' }, 401);
      const body = await readBody(request);
      const cfg = loadAlipayConfig(env);
      if (!cfg.ok) return json({ ok: false, msg: '支付服务未配置' }, 503);
      const r = await alipayGatewayRequest(cfg, 'alipay.trade.fastpay.refund.query', {
        out_trade_no: normName(body.no),
        out_request_no: normName(body.out_request_no),
      });
      if (r.code !== '10000') return json({ ok: false, msg: '查询失败：' + (r.subMsg || r.msg) });
      return json({ ok: true, refundSuccess: r.refund_status === 'REFUND_SUCCESS', refundStatus: r.refund_status || '' });
    }

    if (path === '/api/admin/payclose' && request.method === 'POST') {
      if (!(await isAdminSession(env, request))) return json({ ok: false, msg: '请先登录后台' }, 401);
      const body = await readBody(request);
      const no = normName(body.no);
      const cfg = loadAlipayConfig(env);
      if (!cfg.ok) return json({ ok: false, msg: '支付服务未配置' }, 503);
      const order = await loadOrder(env, no);
      if (!order) return json({ ok: false, msg: '订单不存在' });
      if (order.status === 'PAID') return json({ ok: false, msg: '订单已支付，不能关闭' });
      const r = await alipayGatewayRequest(cfg, 'alipay.trade.close', { out_trade_no: no });
      if (r.code !== '10000') return json({ ok: false, msg: '关闭失败：' + (r.subMsg || r.msg) });
      order.status = 'CLOSED';
      order.closedAt = payNow();
      await saveOrder(env, order);
      return json({ ok: true, msg: '已关闭' });
    }

    // ---------- 管理员 ----------
    if (path === '/api/admin/login' && request.method === 'POST') {
      const body = await readBody(request);
      const user = normName(body.user);
      const pass = String(body.pass == null ? '' : body.pass);
      if (!env.ADMIN_USER || !env.ADMIN_PASS) return json({ ok: false, msg: '后台未配置' }, 500);
      if (user !== env.ADMIN_USER || pass !== env.ADMIN_PASS) {
        return json({ ok: false, msg: '账号或密码错误' }, 401);
      }
      const token = await createSession(env, user, 'admin', SESSION_TTL_ADMIN);
      return json({ ok: true, token: token });
    }

    if (path.startsWith('/api/admin/')) {
      if (!(await isAdminSession(env, request))) return json({ ok: false, msg: '请先登录后台' }, 401);
      const action = path.slice('/api/admin/'.length);

      if (action === 'list') return json({ ok: true, codes: await loadCodes(env) });

      if (action === 'logs') return json({ ok: true, logs: await loadLogs(env) });

      if (action === 'save' && request.method === 'POST') {
        const body = await readBody(request);
        const code = normCode(body.code);
        if (!code) return json({ ok: false, msg: '兑换码不能为空' });
        if (!/^[A-Z0-9_-]{3,32}$/.test(code)) {
          return json({ ok: false, msg: '兑换码只能包含字母/数字/下划线，3-32 位' });
        }
        const count = parseInt(body.count, 10);
        if (isNaN(count) || count < 0) return json({ ok: false, msg: '次数必须是 ≥0 的整数' });
        const maxUses = Math.max(0, parseInt(body.maxUses, 10) || 0);
        const note = String(body.note || '').slice(0, 40);

        const list = await loadCodes(env);
        const idx = list.findIndex((c) => normCode(c.code) === code);
        if (idx >= 0) list[idx] = { ...list[idx], count: count, maxUses: maxUses, note: note };
        else list.push({ code: code, count: count, maxUses: maxUses, note: note, used: 0 });
        await saveCodes(env, list);
        return json({ ok: true, msg: '已保存', codes: list });
      }

      if (action === 'delete' && request.method === 'POST') {
        const body = await readBody(request);
        const code = normCode(body.code);
        const list = (await loadCodes(env)).filter((c) => normCode(c.code) !== code);
        await saveCodes(env, list);
        return json({ ok: true, msg: '已删除', codes: list });
      }

      if (action === 'reset' && request.method === 'POST') {
        const body = await readBody(request);
        const code = normCode(body.code);
        const list = await loadCodes(env);
        const item = list.find((c) => normCode(c.code) === code);
        if (item) {
          item.used = 0;
          item.lastUsed = '';
          await saveCodes(env, list);
        }
        return json({ ok: true, msg: '已重置使用次数', codes: list });
      }

      // 全部用户列表
      if (action === 'users') {
        let cursor = '';
        const users = [];
        do {
          const page = await env.CODES.list({ prefix: 'user:', cursor: cursor });
          for (const k of page.keys) {
            const u = await env.CODES.get(k.name);
            if (!u) continue;
            try {
              const o = JSON.parse(u);
              users.push({
                username: o.username,
                credits: o.credits,
                createdAt: o.createdAt,
                lastSeen: o.lastSeen,
                historyCount: Array.isArray(o.history) ? o.history.length : 0,
              });
            } catch (e) { /* 跳过坏数据 */ }
          }
          cursor = page.list_complete ? '' : page.cursor;
        } while (cursor);
        users.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
        return json({ ok: true, users: users.slice(0, 200) });
      }

      // 设置某用户次数
      if (action === 'setuser' && request.method === 'POST') {
        const body = await readBody(request);
        const name = normName(body.username);
        const v = parseInt(body.credits, 10);
        if (!name) return json({ ok: false, msg: '账号不能为空' });
        if (isNaN(v) || v < 0) return json({ ok: false, msg: '次数无效' });
        const u = await loadUser(env, name);
        if (!u) return json({ ok: false, msg: '用户不存在' });
        u.credits = v;
        await saveUser(env, u);
        return json({ ok: true, msg: '已设置 ' + name + ' 次数为 ' + v });
      }

      return json({ ok: false, msg: '未知操作' }, 404);
    }

    return json({ ok: false, msg: 'Not Found' }, 404);
  },
};
