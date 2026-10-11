// DueDesk sign-up without email confirmation.
// Creates the account already confirmed (admin API, server-side key never leaves the server);
// the app then logs in with the same email + password. Deploy with verify_jwt = false.
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (d: unknown, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { ...CORS, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  const body = await req.json().catch(() => ({}));
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 254) return json({ error: "BAD_EMAIL" }, 400);
  if (password.length < 6 || password.length > 72) return json({ error: "WEAK_PASSWORD" }, 400);
  const url = Deno.env.get("SUPABASE_URL")!;
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const r = await fetch(`${url}/auth/v1/admin/users`, {
    method: "POST",
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, email_confirm: true }),
  });
  if (r.ok) return json({ ok: true });
  const j = await r.json().catch(() => ({}));
  const msg = String(j.msg || j.message || j.error_description || j.error || "");
  if (r.status === 422 || /already|exists|registered/i.test(msg)) return json({ error: "EXISTS" }, 409);
  if (/password/i.test(msg)) return json({ error: "WEAK_PASSWORD", detail: msg }, 400);
  return json({ error: "FAILED", detail: msg }, 500);
});
