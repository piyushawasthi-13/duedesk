// DueDesk: owner turns on login for a tenant (phone number + PIN).
//   POST {action:"set", tenant_id, pin}    + owner's login token → creates/updates the tenant's login
//   POST {action:"remove", tenant_id}      + owner's login token → turns the tenant's login off
// The tenant's account is phone-based: <10 digits>@tenant.duedesk.app, password derived from the PIN.
// The app uses the same rule (pinPassword / phoneEmail) when the tenant logs in.
// Deploy with verify_jwt = false (it checks the owner's token itself).
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (d: unknown, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { ...CORS, "Content-Type": "application/json" } });
const URL_ = () => Deno.env.get("SUPABASE_URL")!;
const KEY = () => Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = (path: string, init: RequestInit = {}) =>
  fetch(`${URL_()}${path}`, { ...init, headers: { apikey: KEY(), Authorization: `Bearer ${KEY()}`, "Content-Type": "application/json" } });
async function rpc(name: string, args: Record<string, unknown>) {
  const r = await admin(`/rest/v1/rpc/${name}`, { method: "POST", body: JSON.stringify(args) });
  const t = await r.text();
  if (!r.ok) throw new Error(`${name}: ${t}`);
  return t ? JSON.parse(t) : null;
}
export const phoneDigits = (p: string) => { let d = String(p || "").replace(/\D/g, ""); if (d.length > 10) d = d.slice(-10); return d; };
export const phoneEmail = (d: string) => `${d}@tenant.duedesk.app`;
export const pinPassword = (pin: string) => `DD-pin-${pin}-tenant`;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  try {
    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    const ur = await fetch(`${URL_()}/auth/v1/user`, { headers: { apikey: KEY(), Authorization: `Bearer ${token}` } });
    if (!ur.ok) return json({ error: "LOGIN_REQUIRED" }, 401);
    const me = await ur.json();
    if (me?.user_metadata?.role === "tenant") return json({ error: "NOT_ALLOWED" }, 403);
    const body = await req.json().catch(() => ({}));
    const t = await rpc("svc_tenant_for_owner", { p_owner: me.id, p_tenant: String(body.tenant_id || "") });
    if (!t) return json({ error: "NOT_ALLOWED" }, 403);

    if (body.action === "remove") {
      const r = await admin(`/rest/v1/tenant_logins?tenant_id=eq.${encodeURIComponent(body.tenant_id)}`, { method: "DELETE" });
      return r.ok ? json({ ok: true }) : json({ error: "FAILED" }, 500);
    }
    if (body.action !== "set") return json({ error: "unknown action" }, 400);

    const digits = phoneDigits(t.phone);
    if (!/^[6-9]\d{9}$/.test(digits)) return json({ error: "NO_PHONE" }, 400);
    const pin = String(body.pin || "");
    if (!/^\d{4,6}$/.test(pin)) return json({ error: "BAD_PIN" }, 400);
    const email = phoneEmail(digits), password = pinPassword(pin);

    let uid = await rpc("svc_user_by_email", { p_email: email });
    if (uid) {
      const r = await admin(`/auth/v1/admin/users/${uid}`, { method: "PUT",
        body: JSON.stringify({ password, email_confirm: true, user_metadata: { role: "tenant", phone: digits } }) });
      if (!r.ok) return json({ error: "FAILED", detail: await r.text() }, 500);
    } else {
      const r = await admin(`/auth/v1/admin/users`, { method: "POST",
        body: JSON.stringify({ email, password, email_confirm: true, user_metadata: { role: "tenant", phone: digits } }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return json({ error: "FAILED", detail: j.msg || j.message || "" }, 500);
      uid = j.id;
    }
    await rpc("svc_link_tenant_login", { p_owner: me.id, p_tenant: body.tenant_id, p_user: uid, p_phone: digits });
    return json({ ok: true, phone: digits });
  } catch (e) {
    return json({ error: "FAILED", detail: String((e as Error).message || e) }, 500);
  }
});
