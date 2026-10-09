// ponytail: ONE runnable check for non-trivial shared logic (no frameworks).
const assert = require("assert");
const src = require("fs").readFileSync("server/server.js", "utf8");
for (const name of ["validateJoin", "logIncident", "makeLimiter", "relayModeration", "publicKeysEqual", "getSocketIp"])
  assert(src.includes(`function ${name}(`), `missing shared helper ${name}`);
assert(!src.includes("checkHttpRateLimit("), "duplicate limiter remains");
assert(!src.includes('require("crypto")') || (src.match(/require\("crypto"\)/g) || []).length === 1, "crypto required more than once");
assert((src.match(/saveIncident\(\{/g) || []).length === 1, "saveIncident not centralized");
const cli = require("fs").readFileSync("client/src/App.jsx", "utf8");
for (const name of ["validUser", "buildModeration", "keyFingerprint"])
  assert(cli.includes(`function ${name}(`), `missing client helper ${name}`);
console.log("ponytail check: PASS - shared helpers only, no dupes");
