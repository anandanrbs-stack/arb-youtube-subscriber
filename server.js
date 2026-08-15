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

// ---- Required OAuth env ----
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

// ---- YouTube / UI env ----
const TARGET_CHANNEL_ID =
  process.env.TARGET_CHANNEL_ID || "UCLH3kQlui92HWRSJbrRZ9-A";
const CHANNEL_URL =
  process.env.CHANNEL_URL ||
  `https://www.youtube.com/channel/${TARGET_CHANNEL_ID}`;

// ---- Security / session ----
const SESSION_SECRET = process.env.SESSION_SECRET;

// ---- Timing ----
const GRANT_SECONDS = Number(process.env.GRANT_SECONDS || 900); // 15 minutes
const OAUTH_STATE_SECONDS = 600; // 10 minutes

// ---- New multi-post config ----
// 1) DOWNLOAD_MAP_JSON (recommended): {"psd_001":"https://...","psd_002":"https://..."}
// 2) Backward compatibility: DOWNLOAD_URL (single) becomes key "default"
const DOWNLOAD_MAP_JSON = process.env.DOWNLOAD_MAP_JSON;
const DOWNLOAD_URL = process.env.DOWNLOAD_URL; // optional fallback

// Return URL safety
// Comma-separated hostnames allowed in the return URL, e.g. "anandanrb.blogspot.com,anandanrb.com"
const ALLOWED_RETURN_HOSTS = (process.env.ALLOWED_RETURN_HOSTS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Optional fallback if "return" param not provided
const DEFAULT_RETURN_URL = process.env.BLOGGER_RETURN_URL || "";

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI || !SESSION_SECRET) {
  console.error("Missing required env: GOOGLE_CLIENT_ID/SECRET/REDIRECT_URI/SESSION_SECRET");
  process.exit(1);
}

// Parse download map
let DOWNLOAD_MAP = {};
try {
  if (DOWNLOAD_MAP_JSON) {
    DOWNLOAD_MAP = JSON.parse(DOWNLOAD_MAP_JSON);
  } else if (DOWNLOAD_URL) {
    DOWNLOAD_MAP = { default: DOWNLOAD_URL };
  } else {
    throw new Error("Set DOWNLOAD_MAP_JSON (recommended) or DOWNLOAD_URL (fallback).");
  }
} catch (e) {
  console.error("Invalid DOWNLOAD_MAP_JSON:", e.message);
  process.exit(1);
}

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
  const payload = {
    ok: true,
    iat: Date.now(),
    exp: Date.now() + GRANT_SECONDS * 1000,
  };

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

// ---- Return URL validation (prevents open-redirect abuse) ----
function isAllowedReturnUrl(urlString) {
  if (!urlString) return false;

  let u;
  try {
    u = new URL(urlString);
  } catch {
    return false;
  }

  if (u.protocol !== "https:") return false;

  // If no allowlist provided, fall back to DEFAULT_RETURN_URL host (if set)
  const allowHosts =
    ALLOWED_RETURN_HOSTS.length > 0
      ? ALLOWED_RETURN_HOSTS
      : (DEFAULT_RETURN_URL ? [new URL(DEFAULT_RETURN_URL).hostname] : []);

  if (allowHosts.length === 0) return false;

  const host = u.hostname.toLowerCase();
  return allowHosts.some((h) => host === h.toLowerCase());
}

function buildReturnRedirect(returnUrl, key) {
  const u = new URL(returnUrl);
  u.searchParams.set("subscriber_verified", "1");
  u.searchParams.set("key", key);
  return u.toString();
}

// ---- YouTube API check (must pass oauth2 client, not string token) ----
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

app.get("/", (req, res) => {
  res.type("html").send(`
    <h2>ARB YouTube Subscriber Verification</h2>
    <p>Backend is running.</p>
    <p>Target Channel: ${TARGET_CHANNEL_ID}</p>
  `);
});

function startGoogleAuth(req, res) {
  const key = String(req.query.key || "default").trim();
  const returnUrl = String(req.query.return || DEFAULT_RETURN_URL || "").trim();

  if (!DOWNLOAD_MAP[key]) {
    return res.status(400).send("Invalid download key.");
  }

  if (!isAllowedReturnUrl(returnUrl)) {
    return res.status(400).send("Invalid return URL.");
  }

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

// Support both URLs
app.get("/auth", startGoogleAuth);
app.get("/auth/google", startGoogleAuth);

app.get("/oauth2/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send(`
        <h2>Verification cancelled</h2>
        <p>You must allow YouTube access to verify your subscription.</p>
        <p><a href="${CHANNEL_URL}" target="_blank" rel="noopener">Subscribe on YouTube</a></p>
      `);
    }

    if (!code) return res.status(400).send("Missing OAuth code.");

    const statePayload = validOAuthState(String(state || ""));
    if (!statePayload) return res.status(400).send("Invalid or expired OAuth request.");

    const { key, returnUrl } = statePayload;

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
    return res
      .status(500)
      .send("Unable to verify the YouTube subscription right now. Please try again.");
  }
});

app.get("/download", (req, res) => {
  const payload = verifyPayload(req.cookies.arb_subscriber_grant);
  if (!payload) {
    return res.status(403).send(`
      <h2>Subscriber verification required</h2>
      <p>Please return to the download page and verify your YouTube subscription.</p>
    `);
  }

  const key = String(req.query.key || "default").trim();
  const url = DOWNLOAD_MAP[key];

  if (!url) return res.status(404).send("Invalid download key.");

  return res.redirect(302, url);
});

app.get("/logout", (req, res) => {
  clearGrantCookie(res);
  return res.type("html").send("Logged out. You can close this tab.");
});

app.listen(PORT, () => {
  console.log(`ARB YouTube subscriber gateway running on port ${PORT}`);
});
