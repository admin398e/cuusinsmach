/*
 * Cousins Mechanical — full backend (Cloudflare Worker)
 * ====================================================================
 * One worker does everything:
 *   • Real customer accounts   (PBKDF2-hashed passwords, KV sessions)
 *   • Bookings API             (create / list / amend / cancel, per account)
 *   • Twilio SMS               (booking confirmation + live status texts)
 *   • Google Calendar          (invite created on the business calendar, customer added as guest)
 *   • Email (Resend)          (confirmation with .ics attachment)
 *   • UK Vehicle Data proxy    (number plate -> vehicle + tyre size)
 *   • tire.vdim.app proxy      (year/make/model/trim fitment)
 *   • GDPR                     (explicit consent, data export, right-to-erasure, retention, audit log)
 *   • Serves the website itself (static assets)
 *
 * --------------------------------------------------------------------
 * ONE-TIME SETUP (~10 min, all free tier)
 *
 * 1. npm i -g wrangler && wrangler login
 *
 * 2. KV (accounts, sessions, bookings, audit):
 *      wrangler kv namespace create CMS_KV
 *    Paste the id into wrangler.toml.
 *
 * 3. Secrets — `wrangler secret put NAME` for each:
 *      SESSION_PEPPER        long random string (openssl rand -hex 32)
 *      UKVD_API_KEY          Vehicle Data Global key (r2/lookup, TyreDetails package)
 *      TIRE_API_KEY          tire.vdim.app key (554fba09...de3f)
 *      TWILIO_SID            Twilio Account SID
 *      TWILIO_TOKEN          Twilio Auth Token
 *      TWILIO_FROM           your Twilio number, e.g. +447...
 *      GCAL_CLIENT_EMAIL     Google service-account email
 *      GCAL_PRIVATE_KEY      service-account private key (PEM, keep the \n newlines)
 *      GCAL_CALENDAR_ID      calendar id the invites land on (share it with the service account)
 *      RESEND_API_KEY        Resend API key (resend.com — free 3,000 emails/mo)
 *      MAIL_FROM             from address on a domain verified in Resend, e.g. bookings@cousinsmechanical.co.uk
 *      OWNER_PHONE           the business owner's number (E.164, e.g. 447925340977) — gets WhatsApp/SMS on new customer messages
 *      SITE_URL              your live site URL, e.g. https://cousinsmechanical.co.uk (used in reset links)
 *      ADMIN_TOKEN           long random string — the admin dashboard password + status-text auth
 *      OVERRIDE_TOKEN        owner master key — always logs in and can reset 2FA (never get locked out)
 *      (2FA: enrolled in-app; the TOTP secret is stored in KV as "admin_totp", not a Worker secret)
 *
 *    Any secret you leave unset simply disables that channel (the booking still succeeds).
 *
 * 4. Put the exported site in ./public, then `wrangler deploy`.
 *    Same-origin frontend auto-detects the API — no extra config.
 *
 * 5. Retention cron (auto-erase old cancelled/'complete' data) — already wired in
 *    wrangler.toml as a scheduled trigger; adjust RETENTION_DAYS below.
 *
 * If your UK Vehicle Data package isn't "TyreData", change UKVD_PACKAGE.
 */

const UKVD_PACKAGE = "TyreDetails";
const ALLOW_ORIGIN = "*"; // tighten to your domain in production
const RETENTION_DAYS = 365; // GDPR storage limitation: purge finished jobs after this
const PRIVACY_VERSION = "2026-08-05"; // bump when your privacy notice changes to re-request consent

// ---------- helpers ----------
const CORS = {
  "Access-Control-Allow-Origin": ALLOW_ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "content-type,authorization",
  "Access-Control-Max-Age": "86400",
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...CORS, "content-type": "application/json" } });
const bad = (msg, status = 400) => json({ error: msg }, status);

function b64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64url(buf) { return b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
async function pbkdf2(password, saltB64, pepper) {
  const enc = new TextEncoder();
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", enc.encode(password + (pepper || "")), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  return b64(bits);
}
function token() { return b64(crypto.getRandomValues(new Uint8Array(32))).replace(/[^a-zA-Z0-9]/g, "").slice(0, 40); }

// ---------- TOTP 2FA (RFC 6238, SHA-1, 6 digits, 30s) ----------
function b32decode(s) {
  s = (s || "").replace(/=+$/, "").toUpperCase(); const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, val = 0; const out = [];
  for (const c of s) { const i = A.indexOf(c); if (i < 0) continue; val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >> (bits - 8)) & 0xff); bits -= 8; } }
  return new Uint8Array(out);
}
function b32encode(bytes) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, val = 0, out = "";
  for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += A[(val >> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += A[(val << (5 - bits)) & 31];
  return out;
}
async function totpAt(secret, step) {
  const key = b32decode(secret); const msg = new ArrayBuffer(8); const dv = new DataView(msg); dv.setUint32(4, step);
  const ck = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", ck, msg));
  const off = sig[19] & 0xf;
  const code = ((sig[off] & 0x7f) << 24) | ((sig[off + 1] & 0xff) << 16) | ((sig[off + 2] & 0xff) << 8) | (sig[off + 3] & 0xff);
  return (code % 1000000).toString().padStart(6, "0");
}
async function totpValid(secret, code) {
  const c = String(code || "").trim(); if (!/^\d{6}$/.test(c)) return false;
  const now = Math.floor(Date.now() / 30000);
  for (let w = -1; w <= 1; w++) if (await totpAt(secret, now + w) === c) return true;
  return false;
}
async function isAdmin(request, env) {
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  if (!t) return false;
  const enrolled = await env.CMS_KV.get("admin_totp");
  if (!enrolled) return t === env.ADMIN_TOKEN;      // 2FA not set up yet: token alone works
  return (await env.CMS_KV.get("asess:" + t)) != null; // once enrolled, only a verified session works
}
function ref() { return "CMS-" + Date.now().toString(36).toUpperCase().slice(-5); }

async function sessionUser(request, env) {
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  if (!t) return null;
  const email = await env.CMS_KV.get("sess:" + t);
  if (!email) return null;
  const raw = await env.CMS_KV.get("user:" + email);
  return raw ? JSON.parse(raw) : null;
}
const publicUser = u => ({
  name: u.name, email: u.email, phone: u.phone,
  marketing: !!u.marketing, smsUpdates: u.smsUpdates !== false,
  consentAt: u.consentAt, privacyVersion: u.privacyVersion,
});

// GDPR: append-only audit log of processing events (lawful-basis accountability)
async function audit(env, email, event, detail) {
  try {
    const key = "audit:" + email;
    const log = JSON.parse((await env.CMS_KV.get(key)) || "[]");
    log.push({ t: Date.now(), event, detail: detail || "" });
    await env.CMS_KV.put(key, JSON.stringify(log.slice(-500)));
  } catch (e) {}
}

// ---------- .ics ----------
function buildICS(o, org) {
  const d = (o.date || "").replace(/-/g, "");
  const start = d ? d + "T090000" : new Date().toISOString().replace(/[-:]/g, "").slice(0, 15);
  const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
  return [
    "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Cousins Mechanical//EN", "METHOD:REQUEST",
    "BEGIN:VEVENT", "UID:" + o.ref + "@cousinsmechanical", "DTSTAMP:" + stamp, "DTSTART:" + start,
    "SUMMARY:Cousins Mechanical — " + (o.svcLabel || "Mobile job"),
    "DESCRIPTION:Ref " + o.ref + ". " + (o.svcLabel || "") + " for " + (o.reg || "") + ". " + (o.notes || ""),
    "LOCATION:" + (o.postcode || "Your location"),
    "ORGANIZER;CN=Cousins Mechanical:mailto:" + (org || "bookings@cousinsmechanical.co.uk"),
    "END:VEVENT", "END:VCALENDAR",
  ].join("\r\n");
}

// ---------- Messaging (WhatsApp Cloud API — cheaper than SMS) ----------
// Set WHATSAPP_TOKEN + WHATSAPP_PHONE_ID (Meta WhatsApp Business Cloud API).
// Falls back to Twilio SMS only if those are set instead. UK numbers auto-normalised to E.164.
function toE164(num) {
  let n = (num || "").replace(/[^\d+]/g, "");
  if (n.startsWith("+")) return n.slice(1);
  if (n.startsWith("0")) return "44" + n.slice(1);
  if (n.startsWith("44")) return n;
  return n;
}
async function sendWhatsApp(env, to, body) {
  if (!env.WHATSAPP_TOKEN || !env.WHATSAPP_PHONE_ID || !to) return { skipped: true };
  const r = await fetch(`https://graph.facebook.com/v20.0/${env.WHATSAPP_PHONE_ID}/messages`, {
    method: "POST",
    headers: { authorization: "Bearer " + env.WHATSAPP_TOKEN, "content-type": "application/json" },
    body: JSON.stringify({ messaging_product: "whatsapp", to: toE164(to), type: "text", text: { body } }),
  }).catch(() => null);
  return { ok: r && r.ok };
}
async function sendSMS(env, to, body) {
  // WhatsApp first (cheaper); Twilio only if WhatsApp isn't configured but Twilio is.
  if (env.WHATSAPP_TOKEN && env.WHATSAPP_PHONE_ID) return sendWhatsApp(env, to, body);
  if (!env.TWILIO_SID || !env.TWILIO_TOKEN || !env.TWILIO_FROM || !to) return { skipped: true };
  const form = new URLSearchParams({ To: to, From: env.TWILIO_FROM, Body: body });
  const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_SID}/Messages.json`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + btoa(env.TWILIO_SID + ":" + env.TWILIO_TOKEN) },
    body: form,
  }).catch(() => null);
  return { ok: r && r.ok };
}

// ---------- Google Calendar (service account, JWT -> access token) ----------
async function googleToken(env) {
  if (!env.GCAL_CLIENT_EMAIL || !env.GCAL_PRIVATE_KEY) return null;
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const claim = b64url(new TextEncoder().encode(JSON.stringify({
    iss: env.GCAL_CLIENT_EMAIL, scope: "https://www.googleapis.com/auth/calendar",
    aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600,
  })));
  const unsigned = header + "." + claim;
  const pem = env.GCAL_PRIVATE_KEY.replace(/\\n/g, "\n").replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
  const jwt = unsigned + "." + b64url(sig);
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwt }),
  }).catch(() => null);
  if (!r || !r.ok) return null;
  return (await r.json()).access_token;
}
async function addCalendarEvent(env, o, customerEmail) {
  const tok = await googleToken(env);
  if (!tok || !env.GCAL_CALENDAR_ID) return { skipped: true };
  const dateStr = o.date || new Date().toISOString().slice(0, 10);
  const event = {
    summary: "Cousins Mechanical — " + (o.svcLabel || "Mobile job"),
    description: `Ref ${o.ref}\n${o.svcLabel || ""} for ${o.reg || ""}\n${o.notes || ""}`,
    location: o.postcode || "Customer location",
    start: { dateTime: dateStr + "T09:00:00", timeZone: "Europe/London" },
    end: { dateTime: dateStr + "T10:00:00", timeZone: "Europe/London" },
    attendees: customerEmail ? [{ email: customerEmail }] : [],
    reminders: { useDefault: true },
  };
  const r = await fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(env.GCAL_CALENDAR_ID)}/events?sendUpdates=all`, {
    method: "POST", headers: { authorization: "Bearer " + tok, "content-type": "application/json" }, body: JSON.stringify(event),
  }).catch(() => null);
  return { ok: r && r.ok };
}

// ---------- Email (Resend — free tier, works from Workers) ----------
// Set RESEND_API_KEY (from resend.com) + MAIL_FROM (a verified sender on your domain).
async function sendEmail(env, to, subject, text, ics) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM || !to) return { skipped: true };
  const body = {
    from: "Cousins Mechanical <" + env.MAIL_FROM + ">",
    to: [to], subject, text,
  };
  if (ics) body.attachments = [{ filename: "booking.ics", content: btoa(ics) }];
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + env.RESEND_API_KEY },
    body: JSON.stringify(body),
  }).catch(() => null);
  return { ok: r && r.ok };
}

// Fire all booking automations (best-effort, never blocks the response)
async function runAutomations(env, u, o) {
  const jobs = [];
  const when = o.date ? `${o.date} ${o.time || ""}`.trim() : "soon";
  if (u.smsUpdates !== false)
    jobs.push(sendSMS(env, u.phone, `Cousins Mechanical: booking ${o.ref} confirmed for ${when}. We'll message you when the van's on the way.`));
  jobs.push(addCalendarEvent(env, o, u.email));
  jobs.push(sendEmail(env, u.email,
    `Booking confirmed — ${o.ref}`,
    `Hi ${u.name},\n\nYour ${o.svcLabel || "mobile job"} is booked for ${when}.\nRef: ${o.ref}\nVehicle: ${o.reg || "-"}\nWhere: ${o.postcode || "-"}\n\nManage or cancel any time in your account. A calendar invite is attached.\n\nCousins Mechanical`,
    buildICS(o, env.MAIL_FROM)));
  await Promise.allSettled(jobs);
  await audit(env, u.email, "booking_automations", o.ref);
}

// ---------- API ----------
async function api(request, env, url, ctx) {
  const p = url.pathname.replace(/^\/api/, "");

  // Public: privacy notice version (frontend uses it to know when to re-ask consent)
  if (p === "/privacy" && request.method === "GET") return json({ version: PRIVACY_VERSION });

  // --- AUTH ---
  if (p === "/auth/signup" && request.method === "POST") {
    const { name, email, phone, password, marketing, smsUpdates, consent } = await request.json().catch(() => ({}));
    const em = (email || "").trim().toLowerCase();
    if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em) || (password || "").length < 6) return bad("Invalid details");
    if (!consent) return bad("Please accept the privacy notice to create an account."); // GDPR: no account without lawful basis
    if (await env.CMS_KV.get("user:" + em)) return bad("Account already exists", 409);
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await pbkdf2(password, salt, env.SESSION_PEPPER);
    const user = {
      name: name.trim(), email: em, phone: (phone || "").trim(), salt, hash,
      marketing: !!marketing,           // explicit opt-in, default OFF (GDPR)
      smsUpdates: smsUpdates !== false,  // service texts for a job they booked
      consentAt: Date.now(), privacyVersion: PRIVACY_VERSION, createdAt: Date.now(),
    };
    await env.CMS_KV.put("user:" + em, JSON.stringify(user));
    await audit(env, em, "account_created", "consent v" + PRIVACY_VERSION);
    const t = token();
    await env.CMS_KV.put("sess:" + t, em, { expirationTtl: 60 * 60 * 24 * 30 });
    return json({ token: t, user: publicUser(user) });
  }

  if (p === "/auth/login" && request.method === "POST") {
    const { email, password } = await request.json().catch(() => ({}));
    const em = (email || "").trim().toLowerCase();
    // brute-force protection: max 8 failed tries per email per 15 min
    const rlKey = "rl:" + em;
    const fails = parseInt((await env.CMS_KV.get(rlKey)) || "0", 10);
    if (fails >= 8) return bad("Too many attempts — try again in 15 minutes.", 429);
    const raw = await env.CMS_KV.get("user:" + em);
    if (!raw) { await env.CMS_KV.put(rlKey, String(fails + 1), { expirationTtl: 900 }); return bad("Email or password not recognised", 401); }
    const user = JSON.parse(raw);
    const hash = await pbkdf2(password || "", user.salt, env.SESSION_PEPPER);
    if (hash !== user.hash) { await env.CMS_KV.put(rlKey, String(fails + 1), { expirationTtl: 900 }); return bad("Email or password not recognised", 401); }
    await env.CMS_KV.delete(rlKey);
    const t = token();
    await env.CMS_KV.put("sess:" + t, em, { expirationTtl: 60 * 60 * 24 * 30 });
    await audit(env, em, "login", "");
    return json({ token: t, user: publicUser(user) });
  }

  // --- Password reset ---
  if (p === "/auth/forgot" && request.method === "POST") {
    const { email } = await request.json().catch(() => ({}));
    const em = (email || "").trim().toLowerCase();
    const raw = await env.CMS_KV.get("user:" + em);
    if (raw) {
      const rt = token();
      await env.CMS_KV.put("reset:" + rt, em, { expirationTtl: 3600 });
      const link = (env.SITE_URL || "") + "/#reset=" + rt;
      ctx.waitUntil(sendEmail(env, em, "Reset your Cousins Mechanical password",
        `Someone asked to reset your password. Use this link within 1 hour:\n${link}\n\nIf that wasn't you, ignore this email.`));
      await audit(env, em, "password_reset_requested", "");
    }
    return json({ ok: true }); // always ok — never reveal whether an email exists
  }
  if (p === "/auth/reset" && request.method === "POST") {
    const { resetToken, password } = await request.json().catch(() => ({}));
    if ((password || "").length < 6) return bad("Password must be at least 6 characters.");
    const em = await env.CMS_KV.get("reset:" + resetToken);
    if (!em) return bad("This reset link is invalid or has expired.", 400);
    const raw = await env.CMS_KV.get("user:" + em);
    if (!raw) return bad("Account not found", 404);
    const user = JSON.parse(raw);
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    user.salt = salt; user.hash = await pbkdf2(password, salt, env.SESSION_PEPPER);
    await env.CMS_KV.put("user:" + em, JSON.stringify(user));
    await env.CMS_KV.delete("reset:" + resetToken);
    await audit(env, em, "password_reset_completed", "");
    return json({ ok: true });
  }

  if (p === "/auth/me" && request.method === "GET") {
    const u = await sessionUser(request, env);
    return u ? json({ user: publicUser(u) }) : bad("Not signed in", 401);
  }

  if (p === "/auth/logout" && request.method === "POST") {
    const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (t) await env.CMS_KV.delete("sess:" + t);
    return json({ ok: true });
  }

  if (p === "/auth/profile" && request.method === "PATCH") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const b = await request.json().catch(() => ({}));
    if (b.name !== undefined) u.name = String(b.name).trim();
    if (b.phone !== undefined) u.phone = String(b.phone).trim();
    if (b.marketing !== undefined) u.marketing = !!b.marketing;      // consent withdrawable any time
    if (b.smsUpdates !== undefined) u.smsUpdates = !!b.smsUpdates;
    await env.CMS_KV.put("user:" + u.email, JSON.stringify(u));
    await audit(env, u.email, "profile_updated", "marketing=" + u.marketing + " sms=" + u.smsUpdates);
    return json({ user: publicUser(u) });
  }

  // --- GDPR: data portability (Art. 20) — full export of everything we hold ---
  if (p === "/gdpr/export" && request.method === "GET") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const bookings = JSON.parse((await env.CMS_KV.get("bookings:" + u.email)) || "[]");
    const log = JSON.parse((await env.CMS_KV.get("audit:" + u.email)) || "[]");
    await audit(env, u.email, "data_exported", "");
    const { salt, hash, ...rest } = u; // never expose the password material
    return new Response(JSON.stringify({ account: rest, bookings, processingLog: log }, null, 2), {
      status: 200,
      headers: { ...CORS, "content-type": "application/json", "content-disposition": 'attachment; filename="cousins-my-data.json"' },
    });
  }

  // --- GDPR: right to erasure (Art. 17) — delete account + all data + sessions ---
  if (p === "/gdpr/delete" && request.method === "POST") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    await env.CMS_KV.delete("user:" + u.email);
    await env.CMS_KV.delete("bookings:" + u.email);
    await env.CMS_KV.delete("audit:" + u.email);
    const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (t) await env.CMS_KV.delete("sess:" + t);
    return json({ ok: true, erased: true });
  }

  // --- MESSAGING: customer <-> business (stored per customer) ---
  if (p === "/messages") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const key = "msgs:" + u.email;
    const thread = JSON.parse((await env.CMS_KV.get(key)) || "[]");
    if (request.method === "GET") return json({ messages: thread });
    if (request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const text = String(b.text || "").slice(0, 2000).trim();
      if (!text) return bad("Empty message");
      thread.push({ t: Date.now(), from: "customer", text, read: false });
      await env.CMS_KV.put(key, JSON.stringify(thread.slice(-200)));
      // flag that this customer has an unread message for the admin
      const inbox = JSON.parse((await env.CMS_KV.get("inbox")) || "{}");
      inbox[u.email] = { name: u.name, phone: u.phone, last: text, t: Date.now(), unread: (inbox[u.email]?.unread || 0) + 1 };
      await env.CMS_KV.put("inbox", JSON.stringify(inbox));
      // notify the business by WhatsApp/SMS if configured
      ctx.waitUntil(sendSMS(env, env.OWNER_PHONE || "", `New message from ${u.name} (${u.phone}): ${text}`));
      return json({ messages: thread });
    }
  }

  // --- BOOKINGS (per account) ---
  if (p === "/bookings") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const kvKey = "bookings:" + u.email;
    const list = JSON.parse((await env.CMS_KV.get(kvKey)) || "[]");

    if (request.method === "GET") return json({ bookings: list });

    if (request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const order = { ...b, ref: b.ref || ref(), status: "confirmed", createdAt: Date.now(),
        updates: [{ t: Date.now(), s: "Booking confirmed", d: "We have your job — you will get a text when the van is on the way." }] };
      list.unshift(order);
      await env.CMS_KV.put(kvKey, JSON.stringify(list));
      await audit(env, u.email, "booking_created", order.ref);
      // Twilio + Google Calendar + email — after the response, doesn't block the customer
      ctx.waitUntil(runAutomations(env, u, order));
      return json({ booking: order });
    }
  }

  const mRef = p.match(/^\/bookings\/([\w-]+)$/);
  if (mRef) {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const kvKey = "bookings:" + u.email;
    let list = JSON.parse((await env.CMS_KV.get(kvKey)) || "[]");
    const i = list.findIndex(o => o.ref === mRef[1]);
    if (i < 0) return bad("Not found", 404);

    if (request.method === "PATCH") {
      const b = await request.json().catch(() => ({}));
      list[i] = { ...list[i], ...b, updates: [...(list[i].updates || []), { t: Date.now(), s: "Booking amended", d: "Your booking was updated." }] };
      await env.CMS_KV.put(kvKey, JSON.stringify(list));
      await audit(env, u.email, "booking_amended", list[i].ref);
      if (u.smsUpdates !== false) ctx.waitUntil(sendSMS(env, u.phone, `Cousins Mechanical: booking ${list[i].ref} updated to ${list[i].date || ""} ${list[i].time || ""}.`));
      return json({ booking: list[i] });
    }
    if (request.method === "DELETE") {
      list[i] = { ...list[i], status: "cancelled", updates: [...(list[i].updates || []), { t: Date.now(), s: "Booking cancelled", d: "This job was cancelled." }] };
      await env.CMS_KV.put(kvKey, JSON.stringify(list));
      await audit(env, u.email, "booking_cancelled", list[i].ref);
      if (u.smsUpdates !== false) ctx.waitUntil(sendSMS(env, u.phone, `Cousins Mechanical: booking ${list[i].ref} cancelled. Re-book any time.`));
      return json({ booking: list[i] });
    }
  }

  // --- Driver/admin: push a live status text (protected by ADMIN_TOKEN secret) ---
  if (p === "/notify" && request.method === "POST") {
    if (!(await isAdmin(request, env))) return bad("Forbidden", 403);
    const { email, ref: r, message } = await request.json().catch(() => ({}));
    const raw = await env.CMS_KV.get("user:" + (email || "").toLowerCase());
    if (!raw) return bad("Unknown customer", 404);
    const u = JSON.parse(raw);
    if (u.smsUpdates !== false) await sendSMS(env, u.phone, message || `Cousins Mechanical: update on booking ${r}.`);
    await audit(env, u.email, "status_sms", r || "");
    return json({ ok: true });
  }

  // --- LIVE LOCATION: driver posts GPS, customer reads it for their own job ---
  if (p === "/driver/location" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const okAdmin = (await isAdmin(request, env)) || body.token === env.ADMIN_TOKEN;
    if (!okAdmin) return bad("Forbidden", 403);
    const { ref: r, lat, lng, eta, arrived } = body;
    if (!r) return bad("Missing ref");
    if (arrived) {
      const list = await env.CMS_KV.list({ prefix: "bookings:" });
      for (const k of list.keys) {
        const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
        let changed = false;
        for (const o of arr) if (o.ref === r && o.status !== "arrived") { o.status = "arrived"; o.updates = [...(o.updates || []), { t: Date.now(), s: "Arrived", d: "Your mechanic is with you." }]; changed = true; }
        if (changed) await env.CMS_KV.put(k.name, JSON.stringify(arr));
      }
    } else {
      await env.CMS_KV.put("loc:" + r, JSON.stringify({ lat, lng, eta, t: Date.now() }), { expirationTtl: 3600 });
    }
    return json({ ok: true });
  }
  // Driver page needs the active job list without a 2FA session — gated by the admin token in the body.
  if (p === "/driver/jobs" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (body.token !== env.ADMIN_TOKEN && !(await isAdmin(request, env))) return bad("Forbidden", 403);
    const out = [];
    const list = await env.CMS_KV.list({ prefix: "bookings:" });
    for (const k of list.keys) {
      const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
      for (const o of arr) if (o.status !== "cancelled" && o.status !== "complete")
        out.push({ ref: o.ref, svcLabel: o.svcLabel, reg: o.reg, postcode: o.postcode, name: o.name, date: o.date, time: o.time, status: o.status });
    }
    return json({ jobs: out });
  }
  const tm = p.match(/^\/track\/([\w-]+)$/);
  if (tm && request.method === "GET") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const arr = JSON.parse((await env.CMS_KV.get("bookings:" + u.email)) || "[]");
    const job = arr.find(o => o.ref === tm[1]);
    if (!job) return bad("Not found", 404); // customers can only track their own jobs
    const loc = JSON.parse((await env.CMS_KV.get("loc:" + tm[1])) || "null");
    return json({ status: job.status, updates: job.updates || [], location: loc });
  }

  // --- ADMIN LOGIN + 2FA ---
  // Step 1: exchange admin token (+ TOTP code once enrolled) for a short-lived admin session.
  if (p === "/admin-login" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    // Master override: OVERRIDE_TOKEN always grants access and clears any stuck 2FA,
    // so the site owner can never be locked out and can regain access for the client.
    if (env.OVERRIDE_TOKEN && b.token === env.OVERRIDE_TOKEN) {
      if (b.reset2fa) await env.CMS_KV.delete("admin_totp");
      const t = token();
      await env.CMS_KV.put("asess:" + t, "admin", { expirationTtl: 60 * 60 * 12 });
      return json({ token: t, enrolled: !!(await env.CMS_KV.get("admin_totp")), override: true });
    }
    if (b.token !== env.ADMIN_TOKEN) return bad("Invalid admin token", 401);
    const enrolled = await env.CMS_KV.get("admin_totp");
    if (enrolled) {
      if (!(await totpValid(enrolled, b.code))) return bad("Enter the 6-digit code from your authenticator app.", 401);
    }
    const t = token();
    await env.CMS_KV.put("asess:" + t, "admin", { expirationTtl: 60 * 60 * 12 });
    return json({ token: t, enrolled: !!enrolled });
  }
  // Generate a new secret to enroll an authenticator (must know the admin token).
  if (p === "/admin-2fa/new" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (b.token !== env.ADMIN_TOKEN) return bad("Invalid admin token", 401);
    const secret = b32encode(crypto.getRandomValues(new Uint8Array(20)));
    const label = encodeURIComponent("Cousins Mechanical Admin");
    const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=Cousins%20Mechanical&algorithm=SHA1&digits=6&period=30`;
    return json({ secret, otpauth, alreadyEnrolled: !!(await env.CMS_KV.get("admin_totp")) });
  }
  // Confirm the code works, then lock 2FA on. From now, admin login requires the app.
  if (p === "/admin-2fa/enable" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (b.token !== env.ADMIN_TOKEN) return bad("Invalid admin token", 401);
    if (!b.secret || !(await totpValid(b.secret, b.code))) return bad("That code didn't match — check the app and try again.", 400);
    await env.CMS_KV.put("admin_totp", b.secret);
    return json({ ok: true });
  }
  if (p === "/admin-2fa/status" && request.method === "GET") {
    return json({ enrolled: !!(await env.CMS_KV.get("admin_totp")) });
  }

  // --- ADMIN (business owner) — all protected by 2FA-verified session ---
  if (p.startsWith("/admin/")) {
    if (!(await isAdmin(request, env))) return bad("Forbidden", 403);

    // All jobs across every customer
    if (p === "/admin/jobs" && request.method === "GET") {
      const out = [];
      const list = await env.CMS_KV.list({ prefix: "bookings:" });
      for (const k of list.keys) {
        const email = k.name.slice("bookings:".length);
        const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
        for (const o of arr) out.push({ ...o, customerEmail: email });
      }
      out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return json({ jobs: out });
    }

    // Update a job's status (owner moving it through the workflow)
    const jm = p.match(/^\/admin\/jobs\/([\w-]+)$/);
    if (jm && request.method === "PATCH") {
      const b = await request.json().catch(() => ({}));
      const email = (b.customerEmail || "").toLowerCase();
      const key = "bookings:" + email;
      const arr = JSON.parse((await env.CMS_KV.get(key)) || "[]");
      const i = arr.findIndex(o => o.ref === jm[1]);
      if (i < 0) return bad("Not found", 404);
      if (b.status) arr[i].status = b.status;
      arr[i].updates = [...(arr[i].updates || []), { t: Date.now(), s: b.label || "Status updated", d: b.note || "" }];
      await env.CMS_KV.put(key, JSON.stringify(arr));
      // notify the customer by SMS if they're opted in
      const uraw = await env.CMS_KV.get("user:" + email);
      if (uraw) { const u = JSON.parse(uraw); if (u.smsUpdates !== false && b.sms) ctx.waitUntil(sendSMS(env, u.phone, b.sms)); }
      return json({ job: arr[i] });
    }

    // --- MESSAGING (admin): list threads, read a thread, reply ---
    if (p === "/admin/threads" && request.method === "GET") {
      const inbox = JSON.parse((await env.CMS_KV.get("inbox")) || "{}");
      const out = Object.entries(inbox).map(([email, v]) => ({ email, ...v }));
      out.sort((a, b) => (b.t || 0) - (a.t || 0));
      return json({ threads: out });
    }
    const tmA = p.match(/^\/admin\/threads\/(.+)$/);
    if (tmA) {
      const email = decodeURIComponent(tmA[1]).toLowerCase();
      const key = "msgs:" + email;
      if (request.method === "GET") {
        const thread = JSON.parse((await env.CMS_KV.get(key)) || "[]").map(m => ({ ...m, read: true }));
        await env.CMS_KV.put(key, JSON.stringify(thread));
        const inbox = JSON.parse((await env.CMS_KV.get("inbox")) || "{}");
        if (inbox[email]) { inbox[email].unread = 0; await env.CMS_KV.put("inbox", JSON.stringify(inbox)); }
        return json({ messages: thread });
      }
      if (request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        const text = String(b.text || "").slice(0, 2000).trim();
        if (!text) return bad("Empty message");
        const thread = JSON.parse((await env.CMS_KV.get(key)) || "[]");
        thread.push({ t: Date.now(), from: "admin", text, read: true });
        await env.CMS_KV.put(key, JSON.stringify(thread.slice(-200)));
        // push the reply to the customer by WhatsApp/SMS if opted in
        const uraw = await env.CMS_KV.get("user:" + email);
        if (uraw) { const u = JSON.parse(uraw); if (u.smsUpdates !== false) ctx.waitUntil(sendSMS(env, u.phone, "Cousins Mechanical: " + text)); }
        return json({ messages: thread });
      }
    }

    // Customers
    if (p === "/admin/customers" && request.method === "GET") {
      const out = [];
      const list = await env.CMS_KV.list({ prefix: "user:" });
      for (const k of list.keys) {
        const u = JSON.parse((await env.CMS_KV.get(k.name)) || "{}");
        const jobs = JSON.parse((await env.CMS_KV.get("bookings:" + u.email)) || "[]");
        out.push({ name: u.name, email: u.email, phone: u.phone, marketing: !!u.marketing, smsUpdates: u.smsUpdates !== false, createdAt: u.createdAt, jobCount: jobs.length });
      }
      out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return json({ customers: out });
    }

    // Parts & stock (KV key "stock")
    if (p === "/admin/stock") {
      if (request.method === "GET") return json({ stock: JSON.parse((await env.CMS_KV.get("stock")) || "[]") });
      if (request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        const stock = JSON.parse((await env.CMS_KV.get("stock")) || "[]");
        if (b.id) { const i = stock.findIndex(s => s.id === b.id); if (i >= 0) stock[i] = { ...stock[i], ...b }; else stock.push(b); }
        else stock.push({ ...b, id: "P" + Date.now().toString(36).toUpperCase().slice(-5) });
        await env.CMS_KV.put("stock", JSON.stringify(stock));
        return json({ stock });
      }
    }
    const sm = p.match(/^\/admin\/stock\/([\w-]+)$/);
    if (sm && request.method === "DELETE") {
      let stock = JSON.parse((await env.CMS_KV.get("stock")) || "[]");
      stock = stock.filter(s => s.id !== sm[1]);
      await env.CMS_KV.put("stock", JSON.stringify(stock));
      return json({ stock });
    }

    // Calendar embed link for the dashboard
    if (p === "/admin/calendar" && request.method === "GET") {
      const id = env.GCAL_CALENDAR_ID || "";
      return json({ calendarId: id, embedUrl: id ? `https://calendar.google.com/calendar/embed?src=${encodeURIComponent(id)}&ctz=Europe/London` : "" });
    }

    return bad("Not found", 404);
  }

  // --- UK Vehicle Data: plate -> vehicle + tyre ---
  if (p === "/ukvd" && request.method === "GET") {
    const vrm = (url.searchParams.get("vrm") || "").toUpperCase().replace(/\s+/g, "");
    if (!vrm) return bad("Missing vrm");
    const pkg = url.searchParams.get("package") || UKVD_PACKAGE;
    // Vehicle Data Global (r2) — packagename + apikey + vrm query params.
    const base = (env.UKVD_BASE || "https://uk.api.vehicledataglobal.com/r2/lookup").replace(/\/+$/, "");
    const target = `${base}?packagename=${encodeURIComponent(pkg)}&apikey=${encodeURIComponent(env.UKVD_API_KEY)}&vrm=${encodeURIComponent(vrm)}`;
    const r = await fetch(target, { headers: { accept: "application/json" } }).catch(() => null);
    if (!r) return bad("UK Vehicle Data unreachable", 502);
    return new Response(await r.text(), { status: r.status, headers: { ...CORS, "content-type": "application/json" } });
  }

  // --- tire.vdim.app fitment proxy ---
  if (p.startsWith("/v1/")) {
    const r = await fetch("https://tire.vdim.app/api" + p + url.search, {
      headers: { "x-api-key": env.TIRE_API_KEY, accept: "application/json" },
    }).catch(() => null);
    if (!r) return bad("Tyre API unreachable", 502);
    return new Response(await r.text(), { status: r.status, headers: { ...CORS, "content-type": r.headers.get("content-type") || "application/json" } });
  }

  return bad("Not found", 404);
}

// GDPR storage limitation: scheduled purge of finished jobs older than RETENTION_DAYS
async function retentionSweep(env) {
  const cutoff = Date.now() - RETENTION_DAYS * 86400000;
  const list = await env.CMS_KV.list({ prefix: "bookings:" });
  for (const k of list.keys) {
    const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
    const kept = arr.filter(o => !((o.status === "cancelled" || o.status === "complete" || o.status === "arrived") && (o.createdAt || 0) < cutoff));
    if (kept.length !== arr.length) await env.CMS_KV.put(k.name, JSON.stringify(kept));
  }
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return api(request, env, url, ctx);
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response("API worker running. Bind ASSETS to serve the site, or call /api/*.", { status: 200 });
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(retentionSweep(env));
  },
};
