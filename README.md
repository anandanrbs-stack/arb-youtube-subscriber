# ARB YouTube Subscriber Download Gateway

This project verifies an authenticated visitor's YouTube subscription to:

Channel ID:
UCLH3kQlui92HWRSJbrRZ9-A

Flow:
1. Visitor clicks "Fast Download for Subscriber" on Blogger.
2. Backend sends the visitor through Google OAuth.
3. Backend calls YouTube Data API `subscriptions.list` for the authenticated user's subscriptions.
4. It filters for ARB's channel ID.
5. If subscribed, backend issues a short-lived signed HTTP-only cookie and returns the visitor to Blogger.
6. Blogger checks the backend and starts a 30-second countdown.
7. "Download Now" calls the backend `/download` route.
8. Backend only redirects to the real file while the signed verification grant is valid.

IMPORTANT:
- OAuth client secret stays on the backend.
- Do not put the client secret in Blogger.
- Use HTTPS in production.
- The actual file URL is stored in DOWNLOAD_URL on the backend.
- The 30-second countdown is a user-experience requirement, not cryptographic protection. Anyone who has the final public Drive URL can still use it directly. For stronger protection, serve/proxy a non-public file through a controlled storage system.

GOOGLE CLOUD SETUP:
1. Create/select a Google Cloud project.
2. Enable YouTube Data API v3.
3. Configure OAuth consent screen.
4. Create an OAuth 2.0 Client ID of type Web application.
5. Add this exact redirect URI:
   https://YOUR-BACKEND-DOMAIN.example.com/oauth2/callback
6. Copy the client ID and client secret into your backend environment variables.
7. For testing, add test users in the OAuth consent screen if Google requires it.
8. Deploy the backend over HTTPS.
9. Put the deployed backend URL into the Blogger snippet.
10. Set BLOGGER_RETURN_URL to the exact Blogger page containing the snippet.

ENVIRONMENT:
Copy .env.example to .env and fill in every value.

LOCAL TESTING:
npm install
npm start

For production, use a real HTTPS deployment platform and set environment variables in the platform dashboard instead of committing `.env`.

GOOGLE API:
The backend uses:
https://www.googleapis.com/auth/youtube.readonly

and:
subscriptions.list
mine=true
forChannelId=UCLH3kQlui92HWRSJbrRZ9-A

The backend does not ask for permission to subscribe/unsubscribe or modify the user's YouTube content.
