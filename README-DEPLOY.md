# NOOR PREMIUM — Backend Deployment & Frontend Connection

## 1. Local / Worker Development
- Entry file: `backend/worker.js`
- Config file: `backend/wrangler.toml`
- Database schema: `backend/schema.sql`

## 2. Connecting Frontend to Live Worker
1. Deploy the Worker and copy its endpoint URL (for example: `https://noor-premium-api.<subdomain>.workers.dev`).
2. Open `settings.html` in NOOR PREMIUM and save that URL in **API Base URL** (`NOOR_API_BASE_URL`), or set `window.NOOR_API_BASE_URL` before `api.js` loads.
3. Once set, `api.js` routes requests (`health`, `auth`, `catalog`, `watchlist`, `history`, `admin/content`) directly to the Worker and falls back to `localStorage` only if unreachable.
