// ============================================================
// 支付宝统一收单（AI 网页应用收款）· Cloudflare Workers 自包含实现
// ------------------------------------------------------------
// 官方 alipay-sdk npm 包（v4.14.0）的 HTTP 层依赖 urllib@4 → undici
// （需要 Node 原生 socket），在 Cloudflare Workers 运行时不可用。
// 本模块按官方 SDK 同等算法实现：
//   · 请求签名：参数按 key 升序拼接 k=v&（排除 sign，保留 sign_type），
//     RSA-SHA256（WebCrypto RSASSA-PKCS1-v1_5；PKCS#1 私钥在调用侧包装为
//     PKCS#8 DER，不改动原始密钥值、不做格式转换）
//   · 异步通知验签：与 SDK checkNotifySignV2 一致（含 sign_type / 不含 sign_type
//     双次尝试）
//   · 网关调用：全局 fetch POST 表单，响应验签（除 sign/sign_type 外字段）
// 配置全部来自环境变量，未配置时功能明确禁用，无任何 Mock / 固定成功 / 跳过验签旁路。
// ============================================================

const SANDBOX_GATEWAY = 'https://openapi-sandbox.dl.alipaydev.com/gateway.do';

function pad2(n) { return n < 10 ? '0' + n : '' + n; }

// 支付宝要求 yyyy-MM-dd HH:mm:ss（非 ISO）；Workers 默认 UTC，按东八区生成
function formatAlipayTimestamp() {
  const d = new Date(Date.now() + 8 * 3600 * 1000);
  return d.getUTCFullYear() + '-' + pad2(d.getUTCMonth() + 1) + '-' + pad2(d.getUTCDate()) + ' ' +
    pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds());
}

export function loadAlipayConfig(env) {
  const appId = String(env.ALIPAY_APP_ID || '').trim();
  const privateKey = String(env.ALIPAY_APP_PRIVATE_KEY || '').trim();
  const alipayPublicKey = String(env.ALIPAY_ALIPAY_PUBLIC_KEY || '').trim();
  const gateway = String(env.ALIPAY_GATEWAY || '').trim() || SANDBOX_GATEWAY;
  const notifyUrl = String(env.ALIPAY_NOTIFY_URL || '').trim();
  const sellerId = String(env.ALIPAY_SELLER_ID || '').trim();
  const keyType = String(env.ALIPAY_KEY_TYPE || 'PKCS1').trim().toUpperCase() === 'PKCS8' ? 'PKCS8' : 'PKCS1';
  if (!appId || !privateKey || !alipayPublicKey) {
    return { ok: false, missing: [] };
  }
  return { ok: true, appId, privateKey, alipayPublicKey, gateway, notifyUrl, sellerId, keyType };
}

// ---- 签名/验签：WebCrypto（Workers 原生支持；node:crypto createSign 在 Workers 不可用） ----
// PKCS#1 原始私钥在调用侧包装为 PKCS#8 DER（不改密钥内容）；支付宝公钥为 SPKI DER
function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function concatBytes() {
  let total = 0;
  for (const a of arguments) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arguments) { out.set(a, off); off += a.length; }
  return out;
}
function derLenBytes(n) {
  if (n < 128) return [n];
  if (n < 256) return [0x81, n];
  return [0x82, (n >> 8) & 0xff, n & 0xff];
}
function pkcs1ToPkcs8(pkcs1) {
  const version = Uint8Array.of(0x02, 0x01, 0x00);
  const algId = Uint8Array.of(0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00);
  const octet = Uint8Array.of(0x04, ...derLenBytes(pkcs1.length));
  const inner = concatBytes(version, algId, octet, pkcs1);
  return concatBytes(Uint8Array.of(0x30, ...derLenBytes(inner.length)), inner);
}
const RSA_IMPORT = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
const RSA_SIGN = { name: 'RSASSA-PKCS1-v1_5' };

// 参与签名的内容：key 升序，k=v& 连接；exclude 集合内的字段不参与
function buildSignContent(params, exclude) {
  const keys = Object.keys(params)
    .filter((k) => !exclude.has(k) && params[k] !== undefined && params[k] !== null && params[k] !== '')
    .sort();
  return keys.map((k) => k + '=' + params[k]).join('&');
}

async function signRSA2(content, privateKey, keyType) {
  const raw = base64ToBytes(String(privateKey).replace(/\s+/g, ''));
  const pkcs8 = keyType === 'PKCS8' ? raw : pkcs1ToPkcs8(raw);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, RSA_IMPORT, false, ['sign']);
  const sig = await crypto.subtle.sign(RSA_SIGN, key, new TextEncoder().encode(content));
  return bytesToBase64(new Uint8Array(sig));
}

export async function verifyRSA2(content, signBase64, alipayPublicKey, keyType) {
  try {
    const spki = base64ToBytes(String(alipayPublicKey).replace(/\s+/g, ''));
    const key = await crypto.subtle.importKey('spki', spki, RSA_IMPORT, false, ['verify']);
    return await crypto.subtle.verify(RSA_SIGN, key, base64ToBytes(String(signBase64)), new TextEncoder().encode(content));
  } catch (e) {
    return false;
  }
}

// ---- 异步通知验签（与 SDK checkNotifySignV2 语义一致） ----
// params：通知的完整表单字段 map（验签前不丢字段、不改名、不改值）
export async function verifyNotifySign(params, alipayPublicKey) {
  const sign = params.sign;
  if (!sign) return false;
  const withType = buildSignContent(params, new Set(['sign']));
  if (await verifyRSA2(withType, sign, alipayPublicKey)) return true;
  const withoutType = buildSignContent(params, new Set(['sign', 'sign_type']));
  return verifyRSA2(withoutType, sign, alipayPublicKey);
}

// ---- 网关响应验签（响应字段扁平，除 sign/sign_type 外全部参与） ----
export async function verifyResponseSign(data, alipayPublicKey) {
  if (!data || !data.sign || !alipayPublicKey) return null;   // 无签名时由调用方用查询兜底
  const normalized = {};
  for (const k of Object.keys(data)) {
    const v = data[k];
    normalized[k] = (v !== null && typeof v === 'object') ? JSON.stringify(v) : String(v);
  }
  const withType = buildSignContent(normalized, new Set(['sign']));
  if (await verifyRSA2(withType, data.sign, alipayPublicKey)) return true;
  const withoutType = buildSignContent(normalized, new Set(['sign', 'sign_type']));
  return await verifyRSA2(withoutType, data.sign, alipayPublicKey);
}

function toFormBody(params) {
  const parts = [];
  for (const k of Object.keys(params)) {
    parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(params[k]));
  }
  return parts.join('&');
}

async function parseGatewayResponse(response) {
  const raw = await response.text();
  const text = String(raw).replace(/^\uFEFF/, '').trim();
  try {
    return { data: JSON.parse(text), text: text };
  } catch (e) {
    // 网关偶发返回 HTML 错误页，不能当作业务成功
    const err = new Error('支付宝网关返回非 JSON 内容（HTTP ' + response.status + '）');
    err.raw = text.slice(0, 200);
    throw err;
  }
}

// 从网关响应原文中提取 "<method>_response" 键对应的原始 JSON 字符串（响应验签依据）
function extractRawJson(text, key) {
  const marker = '"' + key + '":';
  const i = text.indexOf(marker);
  if (i < 0) return null;
  const start = text.indexOf('"', i + marker.length);
  if (start < 0) return null;
  let j = start + 1;
  while (j < text.length) {
    if (text[j] === '\\') { j += 2; continue; }
    if (text[j] === '"') break;
    j++;
  }
  return text.slice(start, j + 1);
}

// ---- 网关响应验签：对 <method>_response 的 JSON 内容验证外层 sign ----
// 优先用 JSON.parse 后重序列化文本（实测网关签名基准），失败回退响应原文子串（抗转义差异）
export async function verifyResponseRaw(biz, rawJsonText, sign, alipayPublicKey) {
  if (!biz || !sign || !alipayPublicKey) return null;
  if (await verifyRSA2(JSON.stringify(biz), sign, alipayPublicKey)) return true;
  if (rawJsonText) return verifyRSA2(rawJsonText, sign, alipayPublicKey);
  return false;
}

// ---- 服务端交易接口（查询 / 退款 / 退款查询 / 关闭）：exec 等价实现 ----
// 返回：{ code, msg, subCode, subMsg, ...业务字段, _verify: true|false|null }
export async function alipayGatewayRequest(config, method, bizContent) {
  const params = {
    app_id: config.appId,
    method: method,
    format: 'JSON',
    charset: 'utf-8',
    sign_type: 'RSA2',
    sign: '',
    timestamp: formatAlipayTimestamp(),
    version: '1.0',
    biz_content: JSON.stringify(bizContent),
  };
  const content = buildSignContent(params, new Set(['sign']));
  params.sign = await signRSA2(content, config.privateKey, config.keyType);

  const response = await fetch(config.gateway, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
    },
    body: toFormBody(params),
  });
  const { data: envelope, text: rawText } = await parseGatewayResponse(response);
  // 响应为 { "<method>.response": {...}, sign } 嵌套结构；兼容扁平结构
  const respKey = Object.keys(envelope).find((k) => k.endsWith('_response'));
  const data = respKey ? envelope[respKey] : envelope;
  const verifyText = respKey ? extractRawJson(rawText, respKey) : null;
  const result = {
    code: String(data.code || ''),
    msg: String(data.msg || ''),
    subCode: data.sub_code || '',
    subMsg: data.sub_msg || '',
    _verify: respKey ? await verifyResponseRaw(data, verifyText, envelope.sign, config.alipayPublicKey) : null,
  };
  for (const k of Object.keys(data)) {
    if (!(k in result) && k !== 'sign' && k !== 'sign_type') result[k] = data[k];
  }
  return result;
}

// ---- 页面跳转类接口 alipay.trade.page.pay（pageExec 等价实现） ----
// 返回 HTML form 字符串，前端必须渲染并自动提交，禁止 URL 直跳
// return_url 必须对应当前项目真实存在的 GET 路由；无公网 HTTPS 通知地址时省略 notify_url
export async function buildPagePayForm(config, { outTradeNo, totalAmount, subject, returnUrl }) {
  if (!returnUrl) throw new Error('网站支付必须配置同步回跳 return_url');

  const p = {
    app_id: config.appId,
    method: 'alipay.trade.page.pay',
    format: 'JSON',
    charset: 'utf-8',
    sign_type: 'RSA2',
    timestamp: formatAlipayTimestamp(),
    version: '1.0',
    biz_content: JSON.stringify({
      out_trade_no: outTradeNo,
      total_amount: totalAmount,
      subject: subject,
      product_code: 'FAST_INSTANT_TRADE_PAY',
    }),
    return_url: returnUrl,
  };
  if (config.notifyUrl) p.notify_url = config.notifyUrl;
  const content = buildSignContent(p, new Set(['sign']));
  p.sign = await signRSA2(content, config.privateKey, config.keyType);

  const query = Object.keys(p)
    .filter((k) => k !== 'biz_content')
    .map((k) => k + '=' + encodeURIComponent(p[k]))
    .join('&');
  const hidden = Object.keys(p)
    .map((k) => '<input type="hidden" name="' + k + '" value="' + String(p[k]).replace(/"/g, '&quot;') + '">')
    .join('\n');
  return (
    '<form name="punchout_form" method="post" action="' + config.gateway + '?' + query + '">\n' +
    hidden + '\n' +
    '<input type="submit" value="立即支付" style="display:none">\n' +
    '</form>\n' +
    '<script>document.forms[0].submit();</script>'
  );
}

// 交易状态 → 本地业务状态映射（待支付/未知不判成功）
export function mapTradeStatus(tradeStatus) {
  switch (String(tradeStatus || '')) {
    case 'TRADE_SUCCESS':
    case 'TRADE_FINISHED':
      return 'PAID';
    case 'WAIT_BUYER_PAY':
      return 'PENDING';
    case 'TRADE_CLOSED':
      return 'CLOSED';
    default:
      return 'UNKNOWN';
  }
}

// 金额比较：以"元"为单位两位小数字符串精确比较，不用浮点数
export function normalizeAmountText(value) {
  if (value == null) return null;
  const text = String(value).trim();
  const match = text.match(/^(\d+)(?:\.(\d{1,2}))?$/);
  if (!match) return null;
  return match[1] + '.' + (match[2] || '').padEnd(2, '0');
}
