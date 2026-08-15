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

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

const TARGET_CHANNEL_ID =
  process.env.TARGET_CHANNEL_ID || "UCLH3kQlui92HWRSJbrRZ9-A";
const CHANNEL_URL =
  process.env.CHANNEL_URL ||
  "https://www.youtube.com/channel/UCLH3kQlui92HWRSJbrRZ9-A";

const BLOGGER_RETURN_URL = process.env.BLOGGER_RETURN_URL;
const DOWNLOAD_URL = process.env.DOWNLOAD_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;

const GRANT_SECONDS = Number(process.env.GRANT_SECONDS || 900); // 15 minutes
const OAUTH_STATE_SECONDS = 600; // 10 minutes

if (
  !CLIENT_ID ||
  !CLIENT_SECRET ||
  !REDIRECT_URI ||
  !BLOGGER_RETURN_URL ||
  !DOWNLOAD_URL ||
  !SESSION_SECRET
) {
  console.error("Missing required environment variables. Check .env.example.");
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
  const sig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest("base64url");
  return `${body}.${sig}`;
}

function verifyPayload(token) {
  if (!token || !token.includes(".")) return null;

  const [body, sig] = token.split(".");
  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest("base64url");

  // Compare decoded bytes (more correct than comparing utf8 strings)
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

function safeReturnUrl() {
  // Intentionally fixed return URL from env (prevents open-redirect attacks)
  return BLOGGER_RETURN_URL;
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

// ✅ FIXED: accept the OAuth2 client (not an access-token string)
async function isSubscribed(oauth2Client) {
  const youtube = google.youtube({
    version: "v3",
    auth: oauth2Client,
  });

  const response = await youtube.subscriptions.list({
    part: "snippet",
    mine: true,
    forChannelId: TARGET_CHANNEL_ID,
    maxResults: 1,
  });

  return Array.isArray(response.data.items) && response.data.items.length > 0;
}

function oauthStateToken() {
  return signPayload({
    purpose: "youtube_oauth",
    exp: Date.now() + OAUTH_STATE_SECONDS * 1000,
  });
}

function validOAuthState(state) {
  const payload = verifyPayload(state);
  return payload && payload.purpose === "youtube_oauth";
}

app.get("/", (req, res) => {
  res.type("html").send(`
    <h2>ARB YouTube Subscriber Verification</h2>
    <p>Backend is running.</p>
    <p>Channel: ${TARGET_CHANNEL_ID}</p>
  `);
});

// Auth handler (so we can support both /auth and /auth/google)
function startGoogleAuth(req, res) {
  const client = oauthClient();
  const state = oauthStateToken();

  const authUrl = client.generateAuthUrl({
    access_type: "online",
    include_granted_scopes: true,
    prompt: "consent",
    scope: ["https://www.googleapis.com/auth/youtube.readonly"],
    state,
  });

  return res.redirect(authUrl);
}

// Keep your old URL working:
app.get("/auth", startGoogleAuth);

// Also support the URL you tried earlier:
app.get("/auth/google", startGoogleAuth);

app.get("/oauth2/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send(`
        <h2>Verification cancelled</h2>
        <p>You must allow YouTube access to verify your subscription.</p>
        <a href="${CHANNEL_URL}" target="_blank" rel="noopener">Open Anandan RB on YouTube</a>
      `);
    }

    if (!code || !validOAuthState(state)) {
      return res.status(400).send("Invalid or expired OAuth request.");
    }

    const client = oauthClient();
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);

    // ✅ FIXED: pass the oauth client
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
          <p>Please subscribe to <strong>Anandan RB</strong> and then return to the download page.</p>
          <p><a href="${CHANNEL_URL}" target="_blank" rel="noopener">Subscribe to Anandan RB</a></p>
          <p>After subscribing, close this tab and click <strong>Fast Download for Subscriber</strong> again.</p>
        </body>
        </html>
      `);
    }

    setGrantCookie(res);

    const separator = BLOGGER_RETURN_URL.includes("?") ? "&" : "?";
    return res.redirect(`${safeReturnUrl()}${separator}subscriber_verified=1`);
  } catch (err) {
    console.error("OAuth verification error:", err?.response?.data || err);
    return res
      .status(500)
      .send(
        "Unable to verify the YouTube subscription right now. Please try again."
      );
  }
});

app.get("/api/status", (req, res) => {
  const payload = verifyPayload(req.cookies.arb_subscriber_grant);

  if (!payload) {
    return res.status(401).json({
      verified: false,
      message: "Subscriber verification required.",
    });
  }

  return res.json({
    verified: true,
    expiresAt: payload.exp,
  });
});

app.get("/download", (req, res) => {
  const payload = verifyPayload(req.cookies.arb_subscriber_grant);

  if (!payload) {
    return res.status(403).send(`
      <h2>Subscriber verification required</h2>
      <p>Please return to the download page and verify your YouTube subscription.</p>
    `);
  }

  // Kept on the server; not exposed in Blogger source
  return res.redirect(302, DOWNLOAD_URL);
});

app.get("/logout", (req, res) => {
  clearGrantCookie(res);
  return res.redirect(BLOGGER_RETURN_URL);
});

app.listen(PORT, () => {
  console.log(`ARB YouTube subscriber gateway running on port ${PORT}`);
});
