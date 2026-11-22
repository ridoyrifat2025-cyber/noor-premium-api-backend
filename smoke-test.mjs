/* =========================================================
   NOOR PREMIUM — BACKEND API v1 SMOKE TEST
   Run: node ./smoke-test.mjs (with worker running on :8787)
   ========================================================= */

const BASE_URL = (process.env.NOOR_API_BASE_URL || "http://127.0.0.1:8787").replace(/\/+$/, "");

async function run() {
  console.log(`Testing NOOR PREMIUM API at ${BASE_URL} ...`);

  const healthRes = await fetch(`${BASE_URL}/api/v1/health`);
  const healthJson = await healthRes.json();
  if (!healthRes.ok || !healthJson.success) {
    throw new Error(`Health check failed: ${JSON.stringify(healthJson)}`);
  }
  console.log("✔ Health OK:", healthJson.data);

  const catalogRes = await fetch(`${BASE_URL}/api/v1/catalog`);
  const catalogJson = await catalogRes.json();
  if (!catalogRes.ok || !catalogJson.success || !Array.isArray(catalogJson.data?.items)) {
    throw new Error(`Catalog check failed: ${JSON.stringify(catalogJson)}`);
  }
  console.log(`✔ Catalog OK (${catalogJson.data.items.length} published items)`);

  const unauthAdminRes = await fetch(`${BASE_URL}/api/v1/admin/content`);
  if (unauthAdminRes.status !== 401) {
    throw new Error(`Expected 401 for unauthenticated admin request, got ${unauthAdminRes.status}`);
  }
  console.log("✔ Admin role guard OK (401 without session)");

  const historyPostRes = await fetch(`${BASE_URL}/api/v1/history`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contentId: "smoke-check-movie",
      contentType: "movie",
      
      progressPercent: 25
    })
  });
  const historyPostJson = await historyPostRes.json();
  if (!historyPostRes.ok || !historyPostJson.success) {
    throw new Error(`History POST failed: ${JSON.stringify(historyPostJson)}`);
  }
  console.log("✔ Watch history POST OK");

  console.log("All smoke tests passed.");
}

run().catch((err) => {
  console.error("✖ Smoke test failed:", err.message || err);
  process.exit(1);
});
