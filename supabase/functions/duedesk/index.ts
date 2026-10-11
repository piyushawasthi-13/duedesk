// DueDesk server function (Supabase Edge Function, Deno). No external imports.
//
//  POST {action:"vapid"}                     → public push key (created on first call)
//  POST {action:"test"}         + user JWT   → sends a test alert to the caller's phones
//  POST {action:"daily"}        + x-cron-secret (from the 9 AM job) → today's alerts to all owners
//  POST {action:"subscribe", plan, cycle} + user JWT → creates a Razorpay subscription
//  POST {action:"verify", ...checkout response} + user JWT → activates the plan after checkout
//  POST ?razorpay-webhook       + X-Razorpay-Signature → keeps plans in sync (renewals, failures)
//
//  Member pay page (no login, secret link token):
//  POST {action:"portal_order", token, amount}  → Razorpay order on the OWNER's account
//  POST {action:"portal_verify", token, razorpay_*} → checks signature, records payment once, alerts owner
//  POST {action:"portal_sync", token}           → records payments whose page was closed early
//  POST {action:"portal_claim", token, amount, utr} → "I paid by UPI", owner confirms in the app
//  Owner (logged in): {action:"sync"}, {action:"gateway_save", key_id, key_secret, webhook_secret?}, {action:"gateway_remove"}
//  POST ?owner-webhook=<owner id> + X-Razorpay-Signature → optional owner webhook (payment.captured)
//
// Secrets (Edge Functions → Secrets). Only needed for payments:
//   RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET
// Optional: VAPID_SUBJECT (default "mailto:support@duedesk.app"),
//           SERVICE_KEY (only if SUPABASE_SERVICE_ROLE_KEY is not provided in your project)

const env = (k: string) => (typeof Deno !== "undefined" ? Deno.env.get(k) : (globalThis as any).process?.env?.[k]) ?? "";
const enc = new TextEncoder();

// ---------- base64url ----------
export function b64u(buf: ArrayBuffer | Uint8Array): string {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64u(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

// ---------- Web Push (RFC 8291 aes128gcm + RFC 8292 VAPID) ----------
export async function makeVapidKeys() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  return { public: b64u(pub), private: jwk };
}

export async function vapidHeader(endpoint: string, publicKey: string, privateJwk: JsonWebKey, subject: string) {
  const aud = new URL(endpoint).origin;
  const header = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject })));
  const key = await crypto.subtle.importKey("jwk", privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(`${header}.${claims}`));
  return `vapid t=${header}.${claims}.${b64u(sig)}, k=${publicKey}`;
}

async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, bytes: number) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, bytes * 8));
}

export async function encryptPayload(p256dh: string, authSecret: string, payload: Uint8Array) {
  const uaPublic = unb64u(p256dh);
  const auth = unb64u(authSecret);
  const local = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", local.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(auth, shared, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, concat(payload, new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]); // record size 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, ct);
}

export async function sendPush(
  sub: { endpoint: string; p256dh: string; auth: string },
  data: unknown,
  vapid: { public: string; private: JsonWebKey },
  subject: string,
) {
  const body = await encryptPayload(sub.p256dh, sub.auth, enc.encode(JSON.stringify(data)));
  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      Authorization: await vapidHeader(sub.endpoint, vapid.public, vapid.private, subject),
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      TTL: "86400",
      Urgency: "high",
    },
    body,
  });
  return res.status;
}

// ---------- HMAC (Razorpay) ----------
export async function hmacHex(secret: string, msg: string) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
  return [...sig].map((x) => x.toString(16).padStart(2, "0")).join("");
}
export function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

// Razorpay subscription status → DueDesk plan_status
export function mapRazorpay(event: string, status: string): string | null {
  if (event === "subscription.activated" || event === "subscription.charged" || event === "subscription.resumed") return "active";
  if (event === "subscription.pending" || event === "subscription.halted") return "past_due";
  if (event === "subscription.cancelled" || event === "subscription.paused") return "cancelled";
  if (event === "subscription.completed") return "expired";
  if (status === "active" || status === "authenticated") return "active";
  return null;
}

// ---------- alert text ----------
const inr = (n: number) => "₹" + new Intl.NumberFormat("en-IN", { maximumFractionDigits: 0 }).format(Math.round(n));
export function alertText(lang: string, members: number, amount: number, names: string) {
  const list = names.split(", ");
  const shown = list.slice(0, 3).join(", ") + (list.length > 3 ? (lang === "hi" ? ` +${list.length - 3} और` : ` +${list.length - 3} more`) : "");
  if (lang === "hi") {
    return { title: `आज ${members} ${members === 1 ? "सदस्य" : "सदस्यों"} से ${inr(amount)} लेने हैं`, body: shown };
  }
  return { title: `Collect ${inr(amount)} from ${members} ${members === 1 ? "member" : "members"} today`, body: shown };
}

// ---------- Supabase helpers ----------
const SB_URL = () => env("SUPABASE_URL");
const SVC = () => env("SUPABASE_SERVICE_ROLE_KEY") || env("SERVICE_KEY");
function svcHeaders(): Record<string, string> {
  const k = SVC();
  const h: Record<string, string> = { apikey: k, "Content-Type": "application/json" };
  if (k.startsWith("eyJ")) h.Authorization = `Bearer ${k}`;
  return h;
}
async function rpc(name: string, args: Record<string, unknown> = {}) {
  const r = await fetch(`${SB_URL()}/rest/v1/rpc/${name}`, { method: "POST", headers: svcHeaders(), body: JSON.stringify(args) });
  const text = await r.text();
  if (!r.ok) throw new Error(`rpc ${name} ${r.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}
async function userFrom(req: Request): Promise<string | null> {
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const r = await fetch(`${SB_URL()}/auth/v1/user`, { headers: { apikey: SVC(), Authorization: `Bearer ${token}` } });
  if (!r.ok) return null;
  return (await r.json())?.id ?? null;
}
async function vapidKeys(): Promise<{ public: string; private: JsonWebKey }> {
  let v = await rpc("svc_get_vapid");
  if (!v?.public) {
    const k = await makeVapidKeys();
    v = await rpc("svc_set_vapid", { p_public: k.public, p_private: k.private });
  }
  return v;
}
async function pushOwner(owner: string, data: unknown, vapid: { public: string; private: JsonWebKey }) {
  const subs = await rpc("svc_push_targets", { p_owner: owner });
  let sent = 0;
  for (const s of subs || []) {
    try {
      const st = await sendPush(s, data, vapid, env("VAPID_SUBJECT") || "mailto:support@duedesk.app");
      if (st === 404 || st === 410) await rpc("svc_drop_push", { p_endpoint: s.endpoint });
      else if (st >= 200 && st < 300) sent++;
    } catch (_) { /* one bad phone must not stop the rest */ }
  }
  return sent;
}

// ---------- Razorpay ----------
export class RzpError extends Error { status: number; constructor(m: string, st: number) { super(m); this.status = st; } }
async function razorpayWith(keyId: string, keySecret: string, path: string, init: RequestInit = {}) {
  const r = await fetch(`https://api.razorpay.com/v1${path}`, {
    ...init,
    headers: { Authorization: `Basic ${btoa(`${keyId}:${keySecret}`)}`, "Content-Type": "application/json", ...(init.headers || {}) },
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new RzpError(j?.error?.description || `Razorpay ${r.status}`, r.status);
  return j;
}
// DueDesk's own account (owner subscriptions)
const razorpay = (path: string, init: RequestInit = {}) =>
  razorpayWith(env("RAZORPAY_KEY_ID"), env("RAZORPAY_KEY_SECRET"), path, init);

// ---------- member payments (money goes to the owner's own Razorpay account) ----------
async function notifyPaid(r: any, how: "online" | "upi") {
  if (!r || r.already || !r.owner_id) return;
  try {
    const hi = r.lang === "hi";
    const amt = inr(Number(r.amount));
    const msg = how === "online"
      ? { title: hi ? `${r.name} ने ${amt} ऑनलाइन दिए` : `${r.name} paid ${amt} online`, body: hi ? "डैशबोर्ड में जुड़ गया ✓" : "Added to your dashboard ✓" }
      : { title: hi ? `${r.name}: ${amt} UPI से भेजे` : `${r.name} says ${amt} sent by UPI`, body: hi ? "अपने बैंक में देखें और कन्फर्म करें" : "Check your bank and confirm it in DueDesk" };
    await pushOwner(r.owner_id, { ...msg, url: "./", tag: "duedesk-pay" }, await vapidKeys());
  } catch (_) { /* alerts are best-effort */ }
}
// Ask Razorpay whether any still-open orders were paid (member closed the page before we heard back)
async function syncOrders(args: { p_owner?: string; p_token?: string }) {
  const open = await rpc("svc_open_orders", { p_owner: args.p_owner ?? null, p_token: args.p_token ?? null });
  let found = 0;
  for (const o of open || []) {
    try {
      const pays = await razorpayWith(o.key_id, o.key_secret, `/orders/${o.rzp_order_id}/payments`);
      const ok = (pays.items || []).find((p: any) => p.status === "captured" || p.status === "authorized");
      if (ok) {
        const r = await rpc("svc_mark_order_paid", { p_rzp_order: o.rzp_order_id, p_rzp_payment: ok.id, p_token: null });
        if (!r.already) { found++; await notifyPaid(r, "online"); }
      }
    } catch (_) { /* try the rest */ }
  }
  return found;
}
const PUBLIC_ERRORS = ["NOT_FOUND", "BAD_UTR", "BAD_AMOUNT", "TOO_MANY", "DUPLICATE_UTR"];
function publicError(e: unknown) {
  const m = String((e as Error)?.message || e);
  return PUBLIC_ERRORS.find((k) => m.includes(k)) || "SERVER_ERROR";
}

const periodEnd = (s: any, cycle: string) =>
  s?.current_end ? new Date(s.current_end * 1000).toISOString()
                 : new Date(Date.now() + (cycle === "yearly" ? 366 : 31) * 864e5).toISOString();

// ---------- HTTP ----------
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { ...CORS, "Content-Type": "application/json" } });

export async function handler(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  try {
    const url = new URL(req.url);

    // Owner's Razorpay webhook (optional; makes online payments appear even if the member closes the page)
    if (url.searchParams.has("owner-webhook")) {
      const owner = url.searchParams.get("owner-webhook") || "";
      if (!/^[0-9a-f-]{36}$/i.test(owner)) return json({ error: "bad owner" }, 400);
      const raw = await req.text();
      const gw = await rpc("svc_gateway_for", { p_owner: owner });
      const sig = req.headers.get("X-Razorpay-Signature") || "";
      if (!gw?.webhook_secret || !safeEqual(await hmacHex(gw.webhook_secret, raw), sig)) return json({ error: "bad signature" }, 401);
      const ev = JSON.parse(raw);
      const p = ev?.payload?.payment?.entity;
      if ((ev.event === "payment.captured" || ev.event === "order.paid") && p?.order_id) {
        try {
          const r = await rpc("svc_mark_order_paid", { p_rzp_order: p.order_id, p_rzp_payment: p.id, p_token: null });
          await notifyPaid(r, "online");
        } catch (e) {
          if (!String((e as Error).message).includes("NOT_FOUND")) throw e; // not a DueDesk order: ignore
        }
      }
      return json({ ok: true });
    }

    // Razorpay webhook (raw body needed for the signature)
    if (url.searchParams.has("razorpay-webhook")) {
      const raw = await req.text();
      const sig = req.headers.get("X-Razorpay-Signature") || "";
      const secret = env("RAZORPAY_WEBHOOK_SECRET");
      if (!secret || !safeEqual(await hmacHex(secret, raw), sig)) return json({ error: "bad signature" }, 401);
      const ev = JSON.parse(raw);
      const s = ev?.payload?.subscription?.entity;
      if (!s) return json({ ok: true, ignored: ev?.event });
      const notes = s.notes || {};
      await rpc("svc_apply_subscription", {
        p_owner: notes.owner_id || null, p_plan: notes.plan || null,
        p_status: mapRazorpay(ev.event, s.status), p_ends: s.current_end ? new Date(s.current_end * 1000).toISOString() : null,
        p_sub: s.id, p_cycle: notes.cycle || null, p_event: ev.event, p_payload: ev,
      });
      return json({ ok: true });
    }

    const body = await req.json().catch(() => ({}));
    switch (body.action) {
      case "vapid": {
        return json({ publicKey: (await vapidKeys()).public });
      }
      case "daily": {
        const ok = await rpc("svc_check_cron", { p_secret: req.headers.get("x-cron-secret") || "" });
        if (!ok) return json({ error: "forbidden" }, 403);
        const vapid = await vapidKeys();
        const rows = await rpc("svc_due_digest");
        let owners = 0, phones = 0;
        for (const r of rows || []) {
          const t = alertText(r.language, r.members, Number(r.amount), r.names || "");
          const n = await pushOwner(r.owner_id, { ...t, url: "./", tag: "duedesk-daily" }, vapid);
          if (n) { owners++; phones += n; }
        }
        return json({ ok: true, owners, phones });
      }
      case "test": {
        const uid = await userFrom(req);
        if (!uid) return json({ error: "login required" }, 401);
        const n = await pushOwner(uid, { title: "DueDesk", body: body.lang === "hi" ? "अलर्ट चालू हैं ✓" : "Alerts are working ✓", url: "./", tag: "duedesk-test" }, await vapidKeys());
        return json({ ok: true, phones: n });
      }
      case "subscribe": {
        const uid = await userFrom(req);
        if (!uid) return json({ error: "login required" }, 401);
        if (!env("RAZORPAY_KEY_ID") || !env("RAZORPAY_KEY_SECRET")) return json({ error: "PAYMENTS_NOT_CONFIGURED" }, 503);
        const cycle = body.cycle === "yearly" ? "yearly" : "monthly";
        const plan = await rpc("svc_plan_for", { p_plan: String(body.plan || "") });
        const planId = plan && (cycle === "yearly" ? plan.razorpay_plan_yearly : plan.razorpay_plan_monthly);
        if (!plan?.id || plan.id === "trial" || !planId) return json({ error: "PLAN_NOT_CONFIGURED" }, 400);
        const sub = await razorpay("/subscriptions", {
          method: "POST",
          body: JSON.stringify({ plan_id: planId, total_count: cycle === "yearly" ? 10 : 120, customer_notify: 1,
                                 notes: { owner_id: uid, plan: plan.id, cycle } }),
        });
        return json({ subscription_id: sub.id, key_id: env("RAZORPAY_KEY_ID") });
      }
      case "verify": {
        const uid = await userFrom(req);
        if (!uid) return json({ error: "login required" }, 401);
        const { razorpay_payment_id: pid, razorpay_subscription_id: sid, razorpay_signature: sig } = body;
        const expect = await hmacHex(env("RAZORPAY_KEY_SECRET"), `${pid}|${sid}`);
        if (!pid || !sid || !sig || !safeEqual(expect, String(sig))) return json({ error: "bad signature" }, 400);
        const s = await razorpay(`/subscriptions/${sid}`);
        if (s?.notes?.owner_id !== uid) return json({ error: "not your subscription" }, 403);
        await rpc("svc_apply_subscription", {
          p_owner: uid, p_plan: s.notes.plan, p_status: "active", p_ends: periodEnd(s, s.notes.cycle),
          p_sub: sid, p_cycle: s.notes.cycle, p_event: "checkout.verified", p_payload: { payment_id: pid, subscription: s },
        });
        return json({ ok: true, plan: s.notes.plan });
      }
      // ----- member pay page (no login; the secret link is the key) -----
      case "portal_order": {
        const token = String(body.token || "");
        const ctx = await rpc("svc_portal_ctx", { p_token: token });
        if (!ctx) return json({ error: "NOT_FOUND" }, 404);
        if (!ctx.key_id) return json({ error: "ONLINE_OFF" }, 400);
        const amt = Math.round(Number(body.amount));
        if (!(amt >= 1 && amt <= 500000)) return json({ error: "BAD_AMOUNT" }, 400);
        if ((await rpc("svc_recent_orders", { p_token: token })) >= 15) return json({ error: "TOO_MANY" }, 429);
        let order;
        try {
          order = await razorpayWith(ctx.key_id, ctx.key_secret, "/orders", {
            method: "POST",
            body: JSON.stringify({ amount: amt * 100, currency: "INR", receipt: `dd_${Date.now().toString(36)}`, payment_capture: 1,
                                   notes: { duedesk: "1", member: String(ctx.name).slice(0, 60), place: String(ctx.place).slice(0, 60) } }),
          });
        } catch (_) { return json({ error: "GATEWAY_ERROR" }, 502); }
        await rpc("svc_create_order", { p_token: token, p_amount: amt, p_rzp_order: order.id });
        return json({ order_id: order.id, key_id: ctx.key_id, amount: amt * 100, place: ctx.place, name: ctx.name, phone: ctx.phone });
      }
      case "portal_verify": {
        const token = String(body.token || "");
        const ctx = await rpc("svc_portal_ctx", { p_token: token });
        if (!ctx?.key_secret) return json({ error: "NOT_FOUND" }, 404);
        const { razorpay_order_id: oid, razorpay_payment_id: pid, razorpay_signature: sig } = body;
        if (!oid || !pid || !sig || !safeEqual(await hmacHex(ctx.key_secret, `${oid}|${pid}`), String(sig))) return json({ error: "BAD_SIGNATURE" }, 400);
        const r = await rpc("svc_mark_order_paid", { p_rzp_order: oid, p_rzp_payment: pid, p_token: token });
        await notifyPaid(r, "online");
        return json({ ok: true, amount: Number(r.amount), payment: r.payment, balance: Number(r.balance) });
      }
      case "portal_sync": {
        return json({ ok: true, found: await syncOrders({ p_token: String(body.token || "") || "-" }) });
      }
      case "portal_claim": {
        const r = await rpc("svc_submit_claim", { p_token: String(body.token || ""), p_amount: Number(body.amount), p_utr: String(body.utr || "") });
        await notifyPaid({ ...r, already: false }, "upi");
        return json({ ok: true });
      }
      // ----- owner (logged in) -----
      case "sync": {
        const uid = await userFrom(req);
        if (!uid) return json({ error: "login required" }, 401);
        return json({ ok: true, found: await syncOrders({ p_owner: uid }) });
      }
      case "gateway_save": {
        const uid = await userFrom(req);
        if (!uid) return json({ error: "login required" }, 401);
        const keyId = String(body.key_id || "").trim(), keySecret = String(body.key_secret || "").trim();
        if (!/^rzp_(test|live)_[A-Za-z0-9]+$/.test(keyId) || keySecret.length < 10) return json({ error: "BAD_KEYS" }, 400);
        try { await razorpayWith(keyId, keySecret, "/orders?count=1"); }
        catch (e) { return json({ error: (e as RzpError).status === 401 ? "BAD_KEYS" : "GATEWAY_ERROR" }, 400); }
        await rpc("svc_set_gateway", { p_owner: uid, p_key_id: keyId, p_key_secret: keySecret, p_webhook_secret: String(body.webhook_secret || "").trim() });
        return json({ ok: true, webhook_url: `${SB_URL()}/functions/v1/duedesk?owner-webhook=${uid}` });
      }
      case "gateway_remove": {
        const uid = await userFrom(req);
        if (!uid) return json({ error: "login required" }, 401);
        await rpc("svc_clear_gateway", { p_owner: uid });
        return json({ ok: true });
      }
      default:
        return json({ error: "unknown action" }, 400);
    }
  } catch (e) {
    const pub = publicError(e);
    return json({ error: pub === "SERVER_ERROR" ? String((e as Error)?.message || e) : pub }, pub === "SERVER_ERROR" ? 500 : 400);
  }
}

if (typeof Deno !== "undefined") Deno.serve(handler);
