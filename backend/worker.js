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
 */

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

      if (!/^[a-zA-Z0-9_\u4e00-\u9fa5]{2,16}$/.test(username)) {
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

    // ---------- 用户接口 ----------
    if (path.startsWith('/api/user/')) {
      const ctx = await requireUser(env, request);
      if (!ctx) return json({ ok: false, msg: '请先登录' }, 401);
      const action = path.slice('/api/user/'.length);

      if (action === 'me') {
        return json({ ok: true, profile: publicProfile(ctx.user) });
      }

      if (action === 'spend') {
        ctx.user.credits = Math.max(0, (parseInt(ctx.user.credits, 10) || 0) - 1);
        ctx.user.lastSeen = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
        await saveUser(env, ctx.user);
        return json({ ok: true, credits: ctx.user.credits });
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
