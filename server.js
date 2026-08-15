require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const { google } = require("googleapis");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());

const PORT = Number(process.env.PORT || 3000);

// ===== OAuth (User) =====
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

// ===== YouTube =====
const TARGET_CHANNEL_ID = process.env.TARGET_CHANNEL_ID;
const CHANNEL_URL =
  process.env.CHANNEL_URL ||
  (TARGET_CHANNEL_ID ? `https://www.youtube.com/channel/${TARGET_CHANNEL_ID}` : "");

// ===== Security =====
const SESSION_SECRET = process.env.SESSION_SECRET;

// ===== Timing =====
const GRANT_SECONDS = Number(process.env.GRANT_SECONDS || 900); // 15 min
const OAUTH_STATE_SECONDS = 600; // 10 min

// ===== Google Sheets (Download DB) =====
const SHEET_ID = process.env.GOOGLE_SHEETS_ID;
const SHEET_RANGE = process.env.GOOGLE_SHEETS_RANGE || "Downloads!A:D";
const SA_EMAIL = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
let SA_PRIVATE_KEY = process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY;

// Allowed return hosts: "anandanrb.blogspot.com" (comma-separated if more)
const ALLOWED_RETURN_HOSTS = (process.env.ALLOWED_RETURN_HOSTS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// Cache sheet reads (avoid calling Sheets API for every visitor)
const SHEET_CACHE_SECONDS = Number(process.env.SHEET_CACHE_SECONDS || 300); // 5 minutes

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI || !SESSION_SECRET) {
  console.error("Missing env: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, SESSION_SECRET");
  process.exit(1);
}
if (!TARGET_CHANNEL_ID) {
  console.error("Missing env: TARGET_CHANNEL_ID");
  process.exit(1);
}
if (!SHEET_ID || !SA_EMAIL || !SA_PRIVATE_KEY) {
  console.error("Missing env for Sheets: GOOGLE_SHEETS_ID, GOOGLE_SERVICE_ACCOUNT_EMAIL, GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY");
  process.exit(1);
}
if (ALLOWED_RETURN_HOSTS.length === 0) {
  console.error("Missing env: ALLOWED_RETURN_HOSTS (example: anandanrb.blogspot.com)");
  process.exit(1);
}

// Render usually stores private key with \n; convert to real newlines
SA_PRIVATE_KEY = SA_PRIVATE_KEY.replace(/\\n/g, "\n");

// ================= Helpers =================
function oauthClient() {
  return new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
}

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signPayload(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifyPayload(token) {
  if (!token || !token.includes(".")) return null;

  const [body, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");

  const a = Buffer.from(sig, "base64url");
  const b = Buffer.from(expected, "base64url");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}

function setGrantCookie(res) {
  const payload = { ok: true, iat: Date.now(), exp: Date.now() + GRANT_SECONDS * 1000 };
  const token = signPayload(payload);

  res.cookie("arb_subscriber_grant", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: GRANT_SECONDS * 1000,
    path: "/",
  });
}

function clearGrantCookie(res) {
  res.clearCookie("arb_subscriber_grant", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
  });
}

// ===== Return URL allowlist (prevents open-redirect abuse) =====
function isAllowedReturnUrl(urlString) {
  if (!urlString) return false;

  let u;
  try {
    u = new URL(urlString);
  } catch {
    return false;
  }

  if (u.protocol !== "https:") return false;
  const host = u.hostname.toLowerCase();

  // allow exact host OR subdomain of allowed host
  return ALLOWED_RETURN_HOSTS.some((allowed) => host === allowed || host.endsWith("." + allowed));
}

function buildReturnRedirect(returnUrl, key) {
  const u = new URL(returnUrl);
  u.searchParams.set("subscriber_verified", "1");
  u.searchParams.set("key", key);
  return u.toString();
}

// ===== YouTube subscription check =====
async function isSubscribed(oauth2Client) {
  const youtube = google.youtube({ version: "v3", auth: oauth2Client });

  const response = await youtube.subscriptions.list({
    part: "snippet",
    mine: true,
    forChannelId: TARGET_CHANNEL_ID,
    maxResults: 1,
  });

  return Array.isArray(response.data.items) && response.data.items.length > 0;
}

// ===== OAuth state token stores {key, returnUrl} securely =====
function oauthStateToken({ key, returnUrl }) {
  return signPayload({
    purpose: "youtube_oauth",
    key,
    returnUrl,
    exp: Date.now() + OAUTH_STATE_SECONDS * 1000,
  });
}

function validOAuthState(state) {
  const payload = verifyPayload(state);
  if (!payload || payload.purpose !== "youtube_oauth") return null;
  if (!payload.key || !payload.returnUrl) return null;
  return payload;
}

// ================= Google Sheets download lookup =================
let sheetCache = {
  loadedAt: 0,
  map: {}, // key -> { url, enabled, title }
};

async function loadDownloadMapFromSheet() {
  const now = Date.now();
  if (sheetCache.loadedAt && now - sheetCache.loadedAt < SHEET_CACHE_SECONDS * 1000) {
    return sheetCache.map;
  }

  const jwt = new google.auth.JWT({
    email: SA_EMAIL,
    key: SA_PRIVATE_KEY,
    scopes: ["https://www.googleapis.com/auth/spreadsheets.readonly"],
  });

  const sheets = google.sheets({ version: "v4", auth: jwt });

  // Expected columns: A=key, B=title, C=download_url, D=enabled
  const resp = await sheets.spreadsheets.values.get({
    spreadsheetId: SHEET_ID,
    range: SHEET_RANGE,
  });

  const rows = resp.data.values || [];
  const map = {};

  // If first row is headers, this will still work; it just creates a useless "key" entry unless you keep headers
  // Better: keep header row and skip it if it matches "key"
  for (let i = 0; i < rows.length; i++) {
    const [keyRaw, titleRaw, urlRaw, enabledRaw] = rows[i];

    const key = String(keyRaw || "").trim();
    const title = String(titleRaw || "").trim();
    const url = String(urlRaw || "").trim();
    const enabledStr = String(enabledRaw || "").trim().toLowerCase();

    if (!key || key.toLowerCase() === "key") continue;
    if (!url) continue;

    const enabled = enabledStr === "true" || enabledStr === "1" || enabledStr === "yes";
    map[key] = { url, enabled, title };
  }

  sheetCache = { loadedAt: now, map };
  return map;
}

async function getDownloadUrlByKey(key) {
  const map = await loadDownloadMapFromSheet();
  const entry = map[key];
  if (!entry) return null;
  if (!entry.enabled) return { disabled: true };
  return { url: entry.url };
}

// ================= Routes =================
app.get("/", (req, res) => {
  res.type("html").send(`
    <h2>ARB YouTube Subscriber Verification</h2>
    <p>Backend is running.</p>
    <p>Target Channel: ${TARGET_CHANNEL_ID}</p>
  `);
});

// start auth: /auth?key=psd_001&return=https://yourpost...
function startGoogleAuth(req, res) {
  const key = String(req.query.key || "").trim();
  const returnUrl = String(req.query.return || "").trim();

  if (!key) return res.status(400).send("Missing key.");
  if (!isAllowedReturnUrl(returnUrl)) return res.status(400).send("Invalid return URL.");

  const client = oauthClient();
  const state = oauthStateToken({ key, returnUrl });

  const authUrl = client.generateAuthUrl({
    access_type: "online",
    include_granted_scopes: true,
    prompt: "consent",
    scope: ["https://www.googleapis.com/auth/youtube.readonly"],
    state,
  });

  return res.redirect(authUrl);
}

app.get("/auth", startGoogleAuth);
app.get("/auth/google", startGoogleAuth);

app.get("/oauth2/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send(`
        <h2>Verification cancelled</h2>
        <p>You must allow YouTube access to verify your subscription.</p>
        <p><a href="${CHANNEL_URL}" target="_blank" rel="noopener">Subscribe to Anandan RB</a></p>
      `);
    }

    if (!code) return res.status(400).send("Missing OAuth code.");

    const statePayload = validOAuthState(String(state || ""));
    if (!statePayload) return res.status(400).send("Invalid or expired OAuth request.");

    const { key, returnUrl } = statePayload;

    // (optional) check key exists in sheet before doing YouTube check
    const entry = await getDownloadUrlByKey(key);
    if (!entry || entry.disabled) {
      clearGrantCookie(res);
      return res.status(400).send("Invalid/disabled download key.");
    }

    const client = oauthClient();
    const { tokens } = await client.getToken(String(code));
    client.setCredentials(tokens);

    const subscribed = await isSubscribed(client);

    if (!subscribed) {
      clearGrantCookie(res);
      return res.status(200).send(`
        <!doctype html>
        <html>
        <head><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Subscription Required</title></head>
        <body style="font-family:Arial,sans-serif;text-align:center;padding:40px">
          <h2>You are not subscribed yet</h2>
          <p>Please subscribe and then return to the download page.</p>
          <p><a href="${CHANNEL_URL}" target="_blank" rel="noopener">Subscribe to Anandan RB</a></p>
          <p><a href="${returnUrl}" rel="noopener">Back to download page</a></p>
        </body>
        </html>
      `);
    }

    setGrantCookie(res);
    return res.redirect(buildReturnRedirect(returnUrl, key));
  } catch (err) {
    console.error("OAuth verification error:", err?.response?.data || err);
    return res.status(500).send("Unable to verify the YouTube subscription right now. Please try again.");
  }
});

app.get("/download", async (req, res) => {
  try {
    const payload = verifyPayload(req.cookies.arb_subscriber_grant);
    if (!payload) {
      return res.status(403).send(`
        <h2>Subscriber verification required</h2>
        <p>Please return to the download page and verify your YouTube subscription.</p>
      `);
    }

    const key = String(req.query.key || "").trim();
    if (!key) return res.status(400).send("Missing key.");

    const entry = await getDownloadUrlByKey(key);
    if (!entry) return res.status(404).send("Invalid key.");
    if (entry.disabled) return res.status(403).send("This download is disabled.");

    return res.redirect(302, entry.url);
  } catch (err) {
    console.error("Download error:", err?.response?.data || err);
    return res.status(500).send("Download service unavailable. Please try again.");
  }
});

app.get("/api/status", (req, res) => {
  const payload = verifyPayload(req.cookies.arb_subscriber_grant);
  if (!payload) return res.status(401).json({ verified: false });
  return res.json({ verified: true, expiresAt: payload.exp });
});

app.get("/logout", (req, res) => {
  clearGrantCookie(res);
  res.type("html").send("Logged out. You can close this tab.");
});

app.listen(PORT, () => {
  console.log(`ARB YouTube subscriber gateway running on port ${PORT}`);
});
