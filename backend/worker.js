/**
 * GgooAt 兑换码后端（Cloudflare Worker + KV）
 * ------------------------------------------------------------------
 * GET  /api/health                健康检查
 * POST /api/redeem   {code}       兑换（公开，服务端校验 + 计数）
 * POST /api/admin/login           校验管理密钥
 * POST /api/admin/list            码表（需 X-Admin-Key）
 * POST /api/admin/save {code,count,maxUses,note}
 * POST /api/admin/delete {code}
 * POST /api/admin/logs            最近 50 条兑换记录
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key',
  'Access-Control-Max-Age': '86400',
};

const KEY_CODES = 'codes';
const KEY_LOGS = 'logs';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

async function loadCodes(env) {
  const raw = await env.CODES.get(KEY_CODES);
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    return [];
  }
}

async function saveCodes(env, list) {
  await env.CODES.put(KEY_CODES, JSON.stringify(list));
}

async function loadLogs(env) {
  const raw = await env.CODES.get(KEY_LOGS);
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    return [];
  }
}

async function readBody(request) {
  try {
    return await request.json();
  } catch (e) {
    return {};
  }
}

function normCode(code) {
  return String(code == null ? '' : code).trim().toUpperCase();
}

function isAdmin(request, env) {
  const key = request.headers.get('X-Admin-Key') || '';
  return !!env.ADMIN_KEY && key === env.ADMIN_KEY;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    // ---------- 健康检查 ----------
    if (path === '/api/health' || path === '/') {
      const codes = await loadCodes(env);
      return json({ ok: true, service: 'ggooat-redeem', codes: codes.length });
    }

    // ---------- 公开：兑换 ----------
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

      // 记录日志（最多保留 50 条）
      const logs = await loadLogs(env);
      logs.unshift({ code: item.code, time: now, ip: request.headers.get('CF-Connecting-IP') || '-' });
      if (logs.length > 50) logs.length = 50;
      await env.CODES.put(KEY_LOGS, JSON.stringify(logs));
      await saveCodes(env, list);

      const remaining = maxUses > 0 ? Math.max(0, maxUses - item.used) : -1;
      return json({
        ok: true,
        count: parseInt(item.count, 10) || 0,
        msg: '兑换成功',
        remaining: remaining,
      });
    }

    // ---------- 管理接口 ----------
    if (path.startsWith('/api/admin/')) {
      if (!isAdmin(request, env)) return json({ ok: false, msg: '管理密钥错误' }, 401);
      const action = path.slice('/api/admin/'.length);

      if (action === 'login') return json({ ok: true });

      if (action === 'list') {
        return json({ ok: true, codes: await loadCodes(env) });
      }

      if (action === 'logs') {
        return json({ ok: true, logs: await loadLogs(env) });
      }

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
        if (idx >= 0) {
          list[idx] = { ...list[idx], count: count, maxUses: maxUses, note: note };
        } else {
          list.push({ code: code, count: count, maxUses: maxUses, note: note, used: 0 });
        }
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

      return json({ ok: false, msg: '未知操作' }, 404);
    }

    return json({ ok: false, msg: 'Not Found' }, 404);
  },
};
