// Gorilla Yapps server: logins, database, live updates and pictures (all in one file).
import crypto from "node:crypto";
/* ===== lib/core.js ===== */
// Shared server helpers for Gorilla Yapps on Vercel.
// Talks to Upstash Redis over its REST API (no extra packages needed).

// Finds the database settings Vercel adds when you connect Upstash Redis (whatever name prefix it used).
function findRedis() {
  const env = process.env;
  for (const [u, t] of [["KV_REST_API_URL", "KV_REST_API_TOKEN"], ["UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN"]]) if (env[u] && env[t]) return [env[u], env[t]];
  for (const k of Object.keys(env)) {
    if (!/_URL$/.test(k) || !/^https:\/\//.test(env[k] || "") || !/upstash/.test(env[k])) continue;
    const t = env[k.replace(/_URL$/, "_TOKEN")];
    if (t && !/READ_ONLY/.test(k)) return [env[k], t];
  }
  return ["", ""];
}
const [RURL, RTOK] = findRedis();
const configured = () => !!(RURL && RTOK);

class Fail extends Error {
  constructor(status, code, msg) { super(msg); this.status = status; this.code = code; this.publicMessage = msg; }
}

/* ---------- Redis ---------- */
async function pipe(cmds) {
  if (!cmds.length) return [];
  const r = await fetch(RURL.replace(/\/$/, "") + "/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + RTOK, "Content-Type": "application/json" },
    body: JSON.stringify(cmds.map(c => c.map(String)))
  });
  if (!r.ok) throw new Error("Redis HTTP " + r.status + " " + (await r.text()).slice(0, 200));
  const out = await r.json();
  return out.map(x => { if (x && x.error) throw new Error("Redis: " + x.error); return x ? x.result : null; });
}
const cmd = async (...c) => (await pipe([c]))[0];

// Adds entries to the change log (and event list) under one new sequence number.
const APPEND = `local s=redis.call('INCR','seq')
for i=1,#ARGV,2 do
  redis.call('LPUSH',ARGV[i],s..'|'..ARGV[i+1])
  if ARGV[i]=='log' then redis.call('LTRIM','log',0,399) else redis.call('LTRIM',ARGV[i],0,99) end
end
return s`;
const appendCmd = pairs => ["EVAL", APPEND, "0", ...pairs];

/* ---------- documents ---------- */
const SEG = /^[A-Za-z0-9_\-.~:@+]{1,200}$/;
function checkPath(path, kind) {
  if (typeof path !== "string" || path.length > 1000) throw new Fail(400, "bad_path", "Bad path.");
  const seg = path.split("/");
  if (seg.length > 16 || !seg.every(s => SEG.test(s) && s !== "." && s !== "..")) throw new Fail(400, "bad_path", "Bad path.");
  if (kind === "doc" && seg.length % 2 !== 0) throw new Fail(400, "bad_path", "That isn't a document path.");
  if (kind === "col" && seg.length % 2 !== 1) throw new Fail(400, "bad_path", "That isn't a collection path.");
  return seg;
}
const parentOf = path => path.split("/").slice(0, -1).join("/");
const idOf = path => path.split("/").pop();
const parse = v => { if (v == null) return null; try { return JSON.parse(v); } catch (e) { return null; } };

async function getDocs(paths) {
  if (!paths.length) return [];
  const r = await cmd("MGET", ...paths.map(p => "d:" + p));
  return r.map(parse);
}
async function getDoc(path) { return (await getDocs([path]))[0]; }

async function listDocs(colPath, { limit = 0, newestFirst = false } = {}) {
  const key = "c:" + colPath;
  const ids = newestFirst
    ? await cmd("ZREVRANGE", key, 0, (limit ? limit : 0) - 1)
    : await cmd("ZRANGE", key, 0, -1);
  if (!ids || !ids.length) return [];
  const docs = await getDocs(ids.map(id => colPath + "/" + id));
  return ids.map((id, i) => ({ id, data: docs[i] })).filter(x => x.data);
}

// entries: [{path, data|null}] → writes docs, keeps collection indexes, logs the change. Returns new seq.
async function writeDocs(entries) {
  if (!entries.length) return null;
  const cmds = [];
  for (const { path, data } of entries) {
    const col = parentOf(path), id = idOf(path);
    if (data == null) { cmds.push(["DEL", "d:" + path], ["ZREM", "c:" + col, id]); }
    else {
      const score = typeof data.ts === "number" ? data.ts : Date.now();
      cmds.push(["SET", "d:" + path, JSON.stringify(data)], ["ZADD", "c:" + col, score, id]);
    }
  }
  cmds.push(appendCmd(entries.flatMap(e => ["log", e.path])));
  const out = await pipe(cmds);
  return out[out.length - 1];
}

const deepMerge = (a, b) => {
  const o = Array.isArray(a) ? a.slice() : Object.assign({}, a || {});
  for (const [k, v] of Object.entries(b || {})) {
    if (v && typeof v === "object" && !Array.isArray(v) && o[k] && typeof o[k] === "object" && !Array.isArray(o[k])) o[k] = deepMerge(o[k], v);
    else o[k] = v;
  }
  return o;
};

/* ---------- login tokens (signed, no database lookup needed) ---------- */
const SECRET = crypto.createHash("sha256").update("gorilla-yapps:" + (process.env.AUTH_SECRET || RTOK || "dev-only")).digest();
const b64u = b => Buffer.from(b).toString("base64url");
function signToken(uid, pv) {
  const payload = b64u(JSON.stringify({ u: uid, v: pv || 1, e: Date.now() + 1000 * 60 * 60 * 24 * 60 }));
  const sig = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  return payload + "." + sig;
}
function verifyToken(t) {
  if (!t || typeof t !== "string" || !t.includes(".")) return null;
  const [payload, sig] = t.split(".");
  const good = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  if (!sig || sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try { const p = JSON.parse(Buffer.from(payload, "base64url").toString()); if (!p.u || p.e < Date.now()) return null; return { uid: p.u, pv: p.v }; }
  catch (e) { return null; }
}

/* ---------- passwords ---------- */
function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(pw, salt, 32, { N: 16384, r: 8, p: 1 }).toString("hex");
  return { salt, hash };
}
function checkPassword(pw, salt, hash) {
  const h = crypto.scryptSync(pw, salt, 32, { N: 16384, r: 8, p: 1 });
  const want = Buffer.from(hash, "hex");
  return want.length === h.length && crypto.timingSafeEqual(h, want);
}
const randomId = (n = 20) => crypto.randomBytes(n).toString("base64url").replace(/[^A-Za-z0-9]/g, "").slice(0, n) || crypto.randomBytes(8).toString("hex");
const sha256 = t => crypto.createHash("sha256").update(t).digest("hex");

/* ---------- request wrapper ---------- */
async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") return JSON.parse(req.body || "{}");
  const chunks = []; for await (const c of req) chunks.push(c);
  const txt = Buffer.concat(chunks).toString();
  return txt ? JSON.parse(txt) : {};
}
function api(fn) {
  return async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    try {
      if (req.method !== "POST") throw new Fail(405, "method", "Use POST.");
      if (!configured()) throw new Fail(503, "setup", "The database isn't connected yet. In Vercel open Storage, connect an Upstash Redis database to this project, then redeploy.");
      let body; try { body = await readBody(req); } catch (e) { throw new Fail(400, "bad_json", "Bad request."); }
      const auth = verifyToken(String(req.headers.authorization || "").replace(/^Bearer\s+/i, ""));
      const out = await fn(body || {}, auth, req);
      res.status(200).json(out);
    } catch (e) {
      const status = e.status || 500;
      if (status >= 500 && !(e instanceof Fail)) console.error(e);
      res.status(status).json({ error: e.code || "error", message: e.publicMessage || "Something went wrong on the server. Try again." });
    }
  };
}
function needUser(auth) { if (!auth) throw new Fail(401, "auth", "Please log in again."); return auth.uid; }

/* ===== lib/censor.js ===== */
// Server-side swear filter (same list as the app), so it can't be skipped.
const BAD_WORDS = [["fuck",0],["motherfuck",0],["shit",0],["bullshit",0],["bitch",0],["bastard",0],["asshole",0],["dumbass",1],["jackass",1],["dick",1],["cunt",0],["pussy",1],["slut",0],["whore",0],["fag",1],["faggot",0],["retard",0],["nigger",0],["nigga",0],["damn",1],["goddamn",0],["crap",1],["piss",1],["cock",1],["wtf",1],["stfu",1],["tits",1],["porn",0],["dildo",0],["kys",1]];
const LEET = {a:"[a@4*]",e:"[e3*]",i:"[i1!*|]",o:"[o0*]",u:"[uv*]",s:"[s$5]",t:"[t7+]",g:"[g9]",l:"[l1|]",c:"[ck(]",k:"[kc]"};
const BAD_RE = new RegExp(BAD_WORDS.map(([w,strict])=>"(?<![a-z0-9])"+w.split("").map(ch=>(LEET[ch]||ch)+"+").join("[^a-z0-9\\s]*")+(strict?"(?:s|es|ed|ing|y)?(?![a-z0-9])":"[a-z]*")).join("|"),"gi");
const censor = t => String(t ?? "").replace(BAD_RE, "🍌🍌🍌");
const hasBad = t => { BAD_RE.lastIndex = 0; const r = BAD_RE.test(String(t || "")); BAD_RE.lastIndex = 0; return r; };

/* ===== lib/totp.js ===== */
// Checks 6-digit authenticator codes (two-step login) on the server.
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function b32decode(str) {
  const s = String(str || "").replace(/=+$/, "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0, val = 0; const out = [];
  for (const ch of s) { val = (val << 5) | B32.indexOf(ch); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
function at(secret, counter) {
  const msg = Buffer.alloc(8); msg.writeUInt32BE(Math.floor(counter / 4294967296), 0); msg.writeUInt32BE(counter >>> 0, 4);
  const h = crypto.createHmac("sha1", b32decode(secret)).update(msg).digest(), o = h[h.length - 1] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1000000).padStart(6, "0");
}
function totpOk(secret, code) {
  code = String(code || "").replace(/\D/g, ""); if (code.length !== 6) return false;
  const c = Math.floor(Date.now() / 30000);
  return [0, -1, 1].some(w => at(secret, c + w) === code);
}
const totpAt = at;

/* ===== lib/push.js ===== */
// Phone and computer notifications (Web Push), built on Node's own crypto: no extra packages.
// The server makes its own key pair the first time and keeps it in the database.

const pushB64 = buf => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const pushUnb64 = s => Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
const pushHmac = (key, data) => crypto.createHmac("sha256", key).update(data).digest();

// Only real push services, so nobody can make the server send requests to other places.
const PUSH_HOSTS = [/^fcm\.googleapis\.com$/, /^android\.googleapis\.com$/, /(^|\.)push\.services\.mozilla\.com$/, /(^|\.)notify\.windows\.com$/, /^web\.push\.apple\.com$/, /(^|\.)push\.apple\.com$/];
function pushEndpointOk(u) {
  const t = process.env.GY_PUSH_TEST; if (t && typeof u === "string" && u.startsWith(t)) return true; // local tests only
  try { const x = new URL(u); return x.protocol === "https:" && !x.port && PUSH_HOSTS.some(r => r.test(x.hostname)); } catch (e) { return false; }
}
function cleanPushSubs(list) {
  return (Array.isArray(list) ? list : []).filter(s => s && typeof s === "object").map(s => ({
    endpoint: String(s.endpoint || "").slice(0, 600),
    keys: { p256dh: String((s.keys && s.keys.p256dh) || "").slice(0, 120), auth: String((s.keys && s.keys.auth) || "").slice(0, 40) },
    ts: +s.ts || Date.now()
  })).filter(s => pushEndpointOk(s.endpoint) && /^[A-Za-z0-9_-]{80,100}$/.test(s.keys.p256dh) && /^[A-Za-z0-9_-]{16,30}$/.test(s.keys.auth)).slice(-6);
}

let vapidCache = null;
async function vapidKeys() {
  if (vapidCache) return vapidCache;
  let v = null;
  try { v = JSON.parse((await cmd("GET", "vapid:v1")) || "null"); } catch (e) {}
  if (!v || !v.d) {
    const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const jwk = privateKey.export({ format: "jwk" });
    const fresh = { x: jwk.x, y: jwk.y, d: jwk.d };
    await cmd("SET", "vapid:v1", JSON.stringify(fresh), "NX");
    v = JSON.parse(await cmd("GET", "vapid:v1"));
  }
  vapidCache = { jwk: { kty: "EC", crv: "P-256", x: v.x, y: v.y, d: v.d }, pub: pushB64(Buffer.concat([Buffer.from([4]), pushUnb64(v.x), pushUnb64(v.y)])) };
  return vapidCache;
}

// RFC 8291 message encryption (aes128gcm). `fixed` is only used by the tests.
function encryptPush(payload, p256dh, authSecret, fixed) {
  const uaPub = pushUnb64(p256dh), auth = pushUnb64(authSecret);
  const ecdh = crypto.createECDH("prime256v1");
  if (fixed && fixed.asPrivate) ecdh.setPrivateKey(pushUnb64(fixed.asPrivate)); else ecdh.generateKeys();
  const asPub = ecdh.getPublicKey();
  const secret = ecdh.computeSecret(uaPub);
  const salt = fixed && fixed.salt ? pushUnb64(fixed.salt) : crypto.randomBytes(16);
  const prkKey = pushHmac(auth, secret);
  const ikm = pushHmac(prkKey, Buffer.concat([Buffer.from("WebPush: info\0"), uaPub, asPub, Buffer.from([1])]));
  const prk = pushHmac(salt, ikm);
  const cek = pushHmac(prk, Buffer.concat([Buffer.from("Content-Encoding: aes128gcm\0"), Buffer.from([1])])).subarray(0, 16);
  const nonce = pushHmac(prk, Buffer.concat([Buffer.from("Content-Encoding: nonce\0"), Buffer.from([1])])).subarray(0, 12);
  const c = crypto.createCipheriv("aes-128-gcm", cek, nonce);
  const body = Buffer.concat([c.update(Buffer.concat([Buffer.from(payload), Buffer.from([2])])), c.final(), c.getAuthTag()]);
  const rs = Buffer.alloc(4); rs.writeUInt32BE(4096);
  return Buffer.concat([salt, rs, Buffer.from([asPub.length]), asPub, body]);
}

function vapidHeader(endpoint, keys, subject) {
  const aud = new URL(endpoint).origin;
  const head = pushB64(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const claims = pushB64(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject }));
  const key = crypto.createPrivateKey({ key: keys.jwk, format: "jwk" });
  const sig = crypto.sign("sha256", Buffer.from(head + "." + claims), { key, dsaEncoding: "ieee-p1363" });
  return "vapid t=" + head + "." + claims + "." + pushB64(sig) + ", k=" + keys.pub;
}

async function sendOne(sub, payload, keys, subject) {
  const body = encryptPush(JSON.stringify(payload), sub.keys.p256dh, sub.keys.auth);
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 3500);
  try {
    const r = await fetch(sub.endpoint, { method: "POST", signal: ctl.signal, headers: {
      TTL: "86400", Urgency: "high", Topic: String(payload.tag || "gy").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 32) || "gy",
      "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", Authorization: vapidHeader(sub.endpoint, keys, subject)
    }, body });
    return r.status;
  } catch (e) { return 0; } finally { clearTimeout(t); }
}

// Sends one notification to each person (all of their devices). Devices that are gone get removed.
async function sendPushes(list, subject) {
  if (!list || !list.length) return;
  const byUid = new Map();
  for (const p of list.slice(0, 12)) if (p.uid && !byUid.has(p.uid)) byUid.set(p.uid, p.payload);
  const uids = [...byUid.keys()];
  const docs = await getDocs(uids.map(u => "data/users/" + u + "/push"));
  const jobs = [], dead = [];
  let keys = null;
  for (let i = 0; i < uids.length; i++) {
    const subs = cleanPushSubs(docs[i] && docs[i].subs);
    if (!subs.length) continue;
    keys = keys || await vapidKeys();
    for (const s of subs) jobs.push(sendOne(s, byUid.get(uids[i]), keys, subject).then(st => { if (st === 404 || st === 410) dead.push([i, s.endpoint]); }));
  }
  await Promise.allSettled(jobs);
  if (dead.length) {
    const writes = [];
    uids.forEach((u, i) => { const gone = new Set(dead.filter(d => d[0] === i).map(d => d[1])); if (gone.size) writes.push({ path: "data/users/" + u + "/push", data: { subs: cleanPushSubs(docs[i].subs).filter(s => !gone.has(s.endpoint)) } }); });
    try { await writeDocs(writes); } catch (e) {}
  }
}

/* ===== lib/bots.js ===== */
// Built-in helper bots (no AI: every answer comes from the lists and rules below).
// This file runs on the server (website) AND is copied into the page for the Claude app version.
const BOT_LIST = {
  yapbot: { name: "YapBot", fur: "#5865f2", hat: "astronaut", face: "robot", tag: "Helper",
    desc: "Rolls dice, flips coins, answers the magic 8-ball, picks for you and shows server and user info.",
    cmds: [["!help", "See every bot command"], ["!ping", "Check that the bots are awake"], ["!roll", "Roll dice, like !roll 2d6"], ["!flip", "Flip a coin"], ["!8ball", "Ask a yes-or-no question"], ["!choose", "Pick one, like !choose pizza | tacos"], ["!server", "Info about this server"], ["!whois", "Info about someone, like !whois @name"]] },
  funbot: { name: "FunBot", fur: "#ff6fb5", hat: "propeller", face: "silly", tag: "Games",
    desc: "Jokes, animal facts, trivia with banana prizes, a lava monke tag game, hugs and compliments.",
    cmds: [["!joke", "Tell a joke"], ["!fact", "A real animal fact"], ["!monke", "Wise words from a monke"], ["!trivia", "Start a trivia question (winner gets 5 🍌)"], ["!answer", "Answer the trivia, like !answer mars"], ["!rate", "Rate anything out of 10"], ["!hug", "Hug someone, like !hug @name"], ["!compliment", "Say something nice to someone"], ["!infection", "Start a lava monke tag game"], ["!run", "Join the tag game"], ["!tag", "Lava monkes tag people, like !tag @name"], ["!lava", "See who is lava"]] },
  bananabot: { name: "BananaBot", fur: "#f0b232", hat: "chef", face: "happy", tag: "Economy",
    desc: "Check bananas and levels, see the top 5, and give bananas to friends.",
    cmds: [["!bananas", "How many bananas you (or @name) have"], ["!level", "Your level and XP"], ["!top", "Top 5 banana holders"], ["!give", "Give bananas, like !give @name 10"]] },
  modbot: { name: "ModBot", fur: "#3f8fe6", hat: "viking", face: "cool", tag: "Safety",
    desc: "Welcomes new members, warns people who spam, and lets mods give warnings.",
    cmds: [["!rules", "Show the rules"], ["!report", "How to report someone"], ["!warn", "Mods only: !warn @name reason"]] }
};
/* ---------- more bots (server owners add them from Find bots) ---------- */
Object.assign(BOT_LIST, {
  gamebot: { name: "GameBot", fur: "#7e57c2", hat: "cap", face: "cool", tag: "Games", cat: "games",
    desc: "Tic-tac-toe against a friend, rock paper scissors, and a number guessing game.",
    cmds: [["!ttt", "Tic-tac-toe, like !ttt @name"], ["!move", "Your tic-tac-toe move, 1 to 9"], ["!rps", "Rock paper scissors, like !rps rock"], ["!guess", "Start a guess-the-number game"], ["!g", "Make a guess, like !g 42"]] },
  wordbot: { name: "WordBot", fur: "#00897b", hat: "gradcap", face: "normal", tag: "Games", cat: "games",
    desc: "Unscramble words for bananas, and flip text backwards.",
    cmds: [["!scramble", "Get a scrambled word to solve (winner gets 3 🍌)"], ["!unscramble", "Answer the scramble, like !unscramble banana"], ["!reverse", "Flip your text backwards"]] },
  mathbot: { name: "MathBot", fur: "#1e88e5", hat: "gradcap", face: "cool", tag: "Games", cat: "games",
    desc: "Quick math races for bananas and a calculator.",
    cmds: [["!math", "Start a math race (winner gets 3 🍌)"], ["!ans", "Answer the math race, like !ans 12"], ["!calc", "Do math, like !calc 12*4+2"]] },
  petbot: { name: "PetBot", fur: "#8d6e63", hat: "flower", face: "happy", tag: "Fun", cat: "fun",
    desc: "A baby monke the whole server takes care of. Feed it, play with it and give it a name.",
    cmds: [["!pet", "See how the server's pet is doing"], ["!feed", "Feed the pet a banana"], ["!play", "Play with the pet"], ["!nap", "Put the pet down for a nap"], ["!petname", "Name the pet, like !petname Bongo"]] },
  taghelper: { name: "TagHelper", fur: "#2e7d32", hat: "leafcrown", face: "happy", tag: "Gorilla Tag", cat: "gtag",
    desc: "Picks random maps and modes, splits people into teams, and gives playing tips.",
    cmds: [["!maps", "List the maps"], ["!modes", "List the game modes"], ["!randommap", "Pick a random map"], ["!randommode", "Pick a random mode"], ["!teams", "Split people into 2 teams, like !teams @a @b @c @d"], ["!tip", "A tip for playing"]] },
  countbot: { name: "CountBot", fur: "#546e7a", hat: "beanie", face: "normal", tag: "Games", cat: "games",
    desc: "Counting game: everyone counts up together, one number per message. Two in a row by the same person breaks it.",
    cmds: [["!count", "See the current count"], ["!countreset", "Mods only: start the count over"]] },
  hypebot: { name: "HypeBot", fur: "#ff7043", hat: "party", face: "starry", tag: "Fun", cat: "fun",
    desc: "Hypes up your friends when they do something cool.",
    cmds: [["!hype", "Hype someone up, like !hype @name"], ["!gg", "Say GG to someone, like !gg @name"], ["!cheer", "Cheer for the whole server"]] },
  storybot: { name: "StoryBot", fur: "#ab47bc", hat: "wizard", face: "wink", tag: "Fun", cat: "fun",
    desc: "Makes up a silly short story starring you or a friend.",
    cmds: [["!story", "A silly story, like !story @name"]] },
  riddlebot: { name: "RiddleBot", fur: "#5c6bc0", hat: "tophat", face: "normal", tag: "Games", cat: "games",
    desc: "Riddles to solve for bananas.",
    cmds: [["!riddle", "Get a riddle (solver gets 3 🍌)"], ["!solve", "Answer the riddle, like !solve a map"]] },
  wyrbot: { name: "ChoiceBot", fur: "#26a69a", hat: "bandana", face: "silly", tag: "Fun", cat: "fun",
    desc: "Would you rather and this-or-that questions to get chats going.",
    cmds: [["!wyr", "A would you rather question"], ["!thisorthat", "A quick this or that"]] },
  quotebot: { name: "QuoteBot", fur: "#78909c", hat: "pirate", face: "wink", tag: "Fun", cat: "fun",
    desc: "Saves the funniest things people say in your server and brings them back.",
    cmds: [["!addquote", "Save a quote, like !addquote ooga booga forever"], ["!quote", "A random saved quote"], ["!quotes", "How many quotes are saved"]] },
  animalbot: { name: "AnimalBot", fur: "#6d4c41", hat: "mushroom", face: "happy", tag: "Fun", cat: "fun",
    desc: "Animal facts, gorilla facts and animal sounds.",
    cmds: [["!animal", "A fact about a random animal"], ["!gorilla", "A gorilla fact"], ["!sound", "Guess which animal makes this sound"]] }
});
for (const [id, cat] of [["yapbot", "helpers"], ["funbot", "fun"], ["bananabot", "economy"], ["modbot", "safety"]]) BOT_LIST[id].cat = cat;
const BOT_CATS = [["helpers", "Helpers"], ["fun", "Fun"], ["games", "Games"], ["gtag", "Gorilla Tag"], ["economy", "Economy"], ["safety", "Safety"]];

const SCRAMBLE_WORDS = ["banana", "gorilla", "jungle", "monkey", "forest", "canyon", "volcano", "treehouse", "infection", "climb", "branch", "jump", "troop", "friend", "chest", "lava", "beach", "cloud", "basement", "mountain", "rocket", "pirate", "castle", "pizza", "rainbow", "dragon", "planet", "puzzle", "tiger", "parrot", "penguin", "turtle", "shark", "dolphin", "spider", "coconut", "mango", "sunset", "thunder", "glacier"];
const RIDDLES = [["What has keys but can't open locks?", ["a piano", "piano", "keyboard", "a keyboard"]], ["What gets wetter the more it dries?", ["a towel", "towel"]], ["What has hands but can't clap?", ["a clock", "clock"]], ["What has a head and a tail but no body?", ["a coin", "coin"]], ["What can you catch but not throw?", ["a cold", "cold"]], ["What goes up but never comes down?", ["your age", "age"]], ["What has many teeth but can't bite?", ["a comb", "comb"]], ["What has one eye but can't see?", ["a needle", "needle"]], ["What is full of holes but still holds water?", ["a sponge", "sponge"]], ["What can travel around the world while staying in a corner?", ["a stamp", "stamp"]], ["What belongs to you but other people use it more?", ["your name", "name"]], ["What has words but never speaks?", ["a book", "book"]], ["The more you take, the more you leave behind. What are they?", ["footsteps", "steps"]], ["What runs but never walks?", ["water", "a river", "river"]], ["What has a neck but no head?", ["a bottle", "bottle"]], ["What building has the most stories?", ["a library", "library"]]];
const WYR = ["Would you rather be able to fly or be invisible?", "Would you rather live in a treehouse or a castle?", "Would you rather have a pet dragon or a pet dinosaur?", "Would you rather only eat bananas or never eat bananas again?", "Would you rather swim with dolphins or climb with gorillas?", "Would you rather be super fast or super strong?", "Would you rather explore space or the deep ocean?", "Would you rather always be 10 minutes early or 10 minutes late?", "Would you rather talk to animals or speak every language?", "Would you rather have no homework forever or no chores forever?", "Would you rather be a famous YouTuber or a famous athlete?", "Would you rather live where it's always summer or always winter?", "Would you rather have a jetpack or a time machine?", "Would you rather play only one game forever or never play the same game twice?"];
const TOT = ["Pizza or tacos?", "Cats or dogs?", "Morning or night?", "Beach or mountains?", "Summer or winter?", "Infection or casual?", "Forest or canyon?", "Ice cream or cake?", "Books or movies?", "Phone or computer?", "Chocolate or vanilla?", "Sneakers or sandals?", "Space or ocean?", "Hot chocolate or lemonade?"];
const HYPE = ["is absolutely cracked right now!", "just did something legendary!", "is the best monke in the troop!", "has the fastest arms in the jungle!", "can't be stopped!", "is built different!", "just made the whole troop proud!", "is on fire (not the lava kind)!"];
const ANIMAL_FACTS = [["Octopuses", "have three hearts and blue blood."], ["Sloths", "can hold their breath longer than dolphins, up to 40 minutes."], ["Elephants", "can't jump, but they can swim well."], ["Owls", "can turn their heads about 270 degrees."], ["Kangaroos", "can't walk backwards easily."], ["Cows", "have best friends and get stressed when they're apart."], ["Sea otters", "hold hands while they sleep so they don't drift apart."], ["Penguins", "give pebbles to the penguin they like."], ["Butterflies", "taste with their feet."], ["Hummingbirds", "are the only birds that can fly backwards."], ["Koalas", "sleep up to 20 hours a day."], ["Giraffes", "have the same number of neck bones as people: seven."], ["Snails", "can sleep for a long time when it's too dry."], ["Dolphins", "have names for each other made of whistles."]];
const GORILLA_FACTS = ["Gorillas are the largest primates in the world.", "A group of gorillas is called a troop.", "Gorillas share about 98% of their DNA with humans.", "Silverbacks get their name from the gray hair on their backs.", "Gorillas build a new nest to sleep in every night.", "Gorillas mostly eat plants: leaves, stems and fruit.", "Gorillas walk on their knuckles.", "Gorillas can live 35 to 40 years in the wild.", "Baby gorillas ride on their mom's back.", "Each gorilla has a unique noseprint, like a fingerprint.", "Gorillas beat their chests to show they're strong or to say hello."];
const SOUNDS = [["Moo!", ["cow"]], ["Oink!", ["pig"]], ["Hoo hoo!", ["owl"]], ["Quack!", ["duck"]], ["Baa!", ["sheep", "lamb"]], ["Neigh!", ["horse"]], ["Ribbit!", ["frog"]], ["Hiss!", ["snake"]], ["Roar!", ["lion"]], ["Ooh ooh aah aah!", ["monkey", "gorilla", "monke", "ape"]], ["Squeak!", ["mouse"]], ["Buzz!", ["bee"]]];
const TAG_MAPS = ["Forest", "Canyon", "Caves", "Mountains", "City", "Clouds", "Beach", "Basement", "Metropolis", "Rotating"];
const TAG_MODES = ["Infection", "Casual", "Hunt", "Paintbrawl", "Guardian", "Minigames"];
const TAG_TIPS = ["Push off walls with both hands at the same time to go faster.", "Look where you want to go before you jump.", "When you're being chased, change direction a lot.", "Climbing up high gives you a better view of who's coming.", "Take breaks. Your arms will thank you.", "Play in a space with nothing around you so you don't hit anything.", "Practice short, quick arm swings for more control.", "Team up with friends and call out where the lava monke is.", "Stay calm when you're tagged. Everybody gets tagged.", "Be nice in lobbies. Good vibes make better games."];
const STORY = [["One day, ", " found a glowing banana in the forest. ", "It started talking and asked for directions to the beach. ", "They walked there together and became best friends."], ["", " was the fastest monke in the troop. ", "One afternoon a cloud challenged them to a race. ", "They won by a banana, and the cloud rained confetti."], ["Late at night, ", " heard a noise in the treehouse. ", "It was just a sleepy owl looking for a snack. ", "They shared a banana and watched the stars."], ["", " tried to climb the tallest tree in the canyon. ", "Halfway up, a squirrel offered them a ride. ", "They reached the top and saw the whole jungle."], ["", " built a raft out of banana peels. ", "It floated way better than anyone expected. ", "Now everyone in the troop wants one."]];
const QUOTE_LINES = ["Every big climb starts with one reach.", "A good troop beats a fast monke.", "Bananas taste better when you share them.", "Getting tagged is just practice for tagging.", "Be the monke your friends want to play with."];

function tttBoard(b) { const c = i => b[i] || String(i + 1); return "```\n " + c(0) + " | " + c(1) + " | " + c(2) + "\n---+---+---\n " + c(3) + " | " + c(4) + " | " + c(5) + "\n---+---+---\n " + c(6) + " | " + c(7) + " | " + c(8) + "\n```"; }
function tttWin(b) { for (const [a, x, c] of [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]]) if (b[a] && b[a] === b[x] && b[a] === b[c]) return b[a]; return b.every(Boolean) ? "draw" : null; }
function safeCalc(expr) {
  const s = String(expr).replace(/\s+/g, "").replace(/x/gi, "*").replace(/÷/g, "/");
  if (!/^[0-9+\-*/().%]{1,60}$/.test(s)) return null;
  let i = 0;
  const num = () => { let m = /^\d+(\.\d+)?/.exec(s.slice(i)); if (!m) return NaN; i += m[0].length; return +m[0]; };
  const factor = () => { if (s[i] === "-") { i++; return -factor(); } if (s[i] === "(") { i++; const v = expr2(); if (s[i] !== ")") return NaN; i++; return v; } return num(); };
  const term = () => { let v = factor(); while (s[i] === "*" || s[i] === "/" || s[i] === "%") { const o = s[i++], w = factor(); v = o === "*" ? v * w : o === "/" ? v / w : v % w; } return v; };
  const expr2 = () => { let v = term(); while (s[i] === "+" || s[i] === "-") { const o = s[i++], w = term(); v = o === "+" ? v + w : v - w; } return v; };
  const v = expr2();
  return i === s.length && isFinite(v) ? Math.round(v * 1e6) / 1e6 : null;
}
const LONG = 30 * 24 * 3600;
const EXTRA_CMDS = {
  async ttt({ arg, env, me, nm, say, who }) {
    const p = await who(); if (!p) return say("Pick someone to play, like `!ttt @name`");
    if (p.uid === me.uid) return say("You can't play against yourself. Pick a friend!");
    await env.state.set("ttt", { x: me.uid, o: p.uid, xn: me.display || me.name, on: p.display || p.name, b: Array(9).fill(""), turn: "X", until: Date.now() + 10 * 60000 }, 900);
    return say(nm(me) + " (X) vs " + nm(p) + " (O)\n" + tttBoard(Array(9).fill("")) + "\n" + nm(me) + ", your move. Type `!move 1` to `!move 9`.");
  },
  async move({ arg, env, me, nm, say }) {
    const g = await env.state.get("ttt"); if (!g || g.until < Date.now()) return say("No tic-tac-toe game right now. Start one with `!ttt @name`");
    const mine = g.turn === "X" ? g.x : g.o; if (me.uid !== mine) return say(me.uid === g.x || me.uid === g.o ? "It's not your turn yet." : "You're not in this game.");
    const n = parseInt(arg, 10) - 1; if (!(n >= 0 && n < 9)) return say("Pick a square from 1 to 9, like `!move 5`");
    if (g.b[n]) return say("That square is taken. Pick another one.");
    g.b[n] = g.turn; const w = tttWin(g.b);
    if (w) { await env.state.del("ttt"); return say(tttBoard(g.b) + "\n" + (w === "draw" ? "It's a tie!" : "**" + (w === "X" ? g.xn : g.on) + "** wins! GG") ); }
    g.turn = g.turn === "X" ? "O" : "X"; await env.state.set("ttt", g, 900);
    return say(tttBoard(g.b) + "\n**" + (g.turn === "X" ? g.xn : g.on) + "**, your move.");
  },
  async rps({ arg, me, nm, say, r }) {
    const opts = ["rock", "paper", "scissors"], pick = opts.find(o => o.startsWith(String(arg).toLowerCase().trim().slice(0, 1)) && String(arg).trim());
    if (!pick) return say("Pick one: `!rps rock`, `!rps paper` or `!rps scissors`");
    const bot = opts[Math.floor(r() * 3)], win = (pick === "rock" && bot === "scissors") || (pick === "paper" && bot === "rock") || (pick === "scissors" && bot === "paper");
    return say(nm(me) + " picked **" + pick + "**, I picked **" + bot + "**. " + (pick === bot ? "Tie!" : win ? "You win!" : "I win!"));
  },
  async guess({ env, say, r }) {
    const n = 1 + Math.floor(r() * 100); await env.state.set("guess", { n, tries: 0, until: Date.now() + 10 * 60000 }, 900);
    return say("I'm thinking of a number from 1 to 100. Guess with `!g 50`");
  },
  async g({ arg, env, me, nm, say }) {
    const st = await env.state.get("guess"); if (!st || st.until < Date.now()) return say("No guessing game right now. Start one with `!guess`");
    const v = parseInt(arg, 10); if (!(v >= 1 && v <= 100)) return say("Guess a number from 1 to 100, like `!g 42`");
    st.tries++;
    if (v === st.n) { await env.state.del("guess"); const paid = await env.addBananas(me.uid, 2); return say(nm(me) + " got it! It was **" + st.n + "** (" + st.tries + " guesses)." + (paid ? " +2 🍌" : "")); }
    await env.state.set("guess", st, 900); return say(v < st.n ? "Higher!" : "Lower!");
  },
  async scramble({ env, say, r }) {
    const w = SCRAMBLE_WORDS[Math.floor(r() * SCRAMBLE_WORDS.length)];
    let s = w; for (let t = 0; t < 6 && s === w; t++) s = w.split("").sort(() => r() - 0.5).join("");
    await env.state.set("scramble", { w, until: Date.now() + 90000 }, 120);
    return say("Unscramble this: **" + s.toUpperCase() + "**\nAnswer with `!unscramble word`");
  },
  async unscramble({ arg, env, me, nm, say }) {
    const st = await env.state.get("scramble"); if (!st || st.until < Date.now()) return say("No scramble right now. Start one with `!scramble`");
    if (String(arg).toLowerCase().trim() !== st.w) return say("Not quite, " + nm(me) + ". Keep trying!");
    await env.state.del("scramble"); const paid = await env.addBananas(me.uid, 3);
    return say(nm(me) + " got it: **" + st.w + "**!" + (paid ? " +3 🍌" : ""));
  },
  async reverse({ arg, say }) { const t = String(arg).trim().slice(0, 120); return t ? say([...t].reverse().join("")) : say("Type something to flip, like `!reverse banana`"); },
  async math({ env, say, r }) {
    const a = 2 + Math.floor(r() * 12), b = 2 + Math.floor(r() * 12), op = ["+", "-", "×"][Math.floor(r() * 3)];
    const ans = op === "+" ? a + b : op === "-" ? a - b : a * b;
    await env.state.set("math", { ans, until: Date.now() + 60000 }, 90);
    return say("Quick! What's **" + a + " " + op + " " + b + "**? Answer with `!ans number`");
  },
  async ans({ arg, env, me, nm, say }) {
    const st = await env.state.get("math"); if (!st || st.until < Date.now()) return say("No math race right now. Start one with `!math`");
    if (parseInt(arg, 10) !== st.ans) return say("Not quite, " + nm(me) + "!");
    await env.state.del("math"); const paid = await env.addBananas(me.uid, 3);
    return say(nm(me) + " was fastest! It's **" + st.ans + "**." + (paid ? " +3 🍌" : ""));
  },
  async calc({ arg, say }) { const v = safeCalc(arg); return v === null ? say("I can do + - × ÷ and brackets, like `!calc (12+4)*3`") : say("**" + String(arg).trim().slice(0, 60) + "** = **" + v + "**"); },
  async pet({ env, say }) { const p = (await env.state.get("pet")) || { name: "Baby Monke", food: 3, fun: 3 }; return say("**" + p.name + "**\nFood: " + "🍌".repeat(Math.max(0, p.food)) + (p.food ? "" : "hungry!") + "\nFun: " + "★".repeat(Math.max(0, p.fun)) + (p.fun ? "" : "bored!") + "\nTry `!feed`, `!play` or `!nap`"); },
  async feed({ env, me, nm, say }) { const p = (await env.state.get("pet")) || { name: "Baby Monke", food: 3, fun: 3 }; if (p.food >= 5) return say("**" + p.name + "** is full! Try `!play` instead."); p.food++; await env.state.set("pet", p, LONG); return say(nm(me) + " fed **" + p.name + "** a banana. Yum!"); },
  async play({ env, me, nm, say, r }) { const p = (await env.state.get("pet")) || { name: "Baby Monke", food: 3, fun: 3 }; if (p.food <= 0) return say("**" + p.name + "** is too hungry to play. Try `!feed`"); p.fun = Math.min(5, p.fun + 1); p.food = Math.max(0, p.food - 1); await env.state.set("pet", p, LONG); return say(nm(me) + " " + ["played tag with", "swung on vines with", "built a fort with", "had a dance party with"][Math.floor(r() * 4)] + " **" + p.name + "**!"); },
  async nap({ env, say }) { const p = (await env.state.get("pet")) || { name: "Baby Monke", food: 3, fun: 3 }; p.fun = Math.max(0, p.fun - 1); p.food = Math.max(0, p.food - 1); await env.state.set("pet", p, LONG); return say("**" + p.name + "** curled up for a nap. Zzz..."); },
  async petname({ arg, env, say }) { const n = String(arg).replace(/[^A-Za-z0-9 ]/g, "").trim().slice(0, 20); if (n.length < 2) return say("Give it a name, like `!petname Bongo`"); const p = (await env.state.get("pet")) || { name: "Baby Monke", food: 3, fun: 3 }; p.name = n; await env.state.set("pet", p, LONG); return say("The pet is now called **" + n + "**!"); },
  async maps({ say }) { return say("**Maps:** " + TAG_MAPS.join(", ")); },
  async modes({ say }) { return say("**Modes:** " + TAG_MODES.join(", ")); },
  async randommap({ say, r }) { return say("Let's play on **" + TAG_MAPS[Math.floor(r() * TAG_MAPS.length)] + "**!"); },
  async randommode({ say, r }) { return say("Let's play **" + TAG_MODES[Math.floor(r() * TAG_MODES.length)] + "**!"); },
  async teams({ arg, env, say, r }) {
    const names = [...new Set((String(arg).match(/@([A-Za-z0-9_]{2,16})/g) || []).map(x => x.slice(1)))].slice(0, 20);
    if (names.length < 2) return say("Tag at least 2 people, like `!teams @a @b @c @d`");
    const ppl = []; for (const n of names) { const p = await env.findUser(n); ppl.push(p ? (p.display || p.name) : n); }
    for (let i = ppl.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [ppl[i], ppl[j]] = [ppl[j], ppl[i]]; }
    const h = Math.ceil(ppl.length / 2); return say("**Team 1:** " + ppl.slice(0, h).join(", ") + "\n**Team 2:** " + ppl.slice(h).join(", "));
  },
  async tip({ say, r }) { return say("Tip: " + TAG_TIPS[Math.floor(r() * TAG_TIPS.length)]); },
  async count({ env, say }) { const c = (await env.state.get("count")) || { n: 0 }; return say("The count is at **" + c.n + "**. Next number: **" + (c.n + 1) + "**"); },
  async countreset({ env, say }) { if (!env.isMod) return say("Only mods and the owner can reset the count."); await env.state.set("count", { n: 0, last: "" }, LONG); return say("The count is back to 0. Start with **1**!"); },
  async hype({ env, me, nm, say, who, r }) { const p = (await who()) || me; return say(nm(p) + " " + HYPE[Math.floor(r() * HYPE.length)]); },
  async gg({ me, nm, say, who }) { const p = await who(); return say(p ? nm(me) + " says GG to " + nm(p) + "! Great game!" : "GG everyone! Great game!"); },
  async cheer({ say, r }) { return say(["Let's goooo, troop!", "Everybody beat your chest!", "This server is the best server!", "Ooga booga! The troop is unstoppable!"][Math.floor(r() * 4)]); },
  async story({ me, nm, say, who, r }) { const p = (await who()) || me, s = STORY[Math.floor(r() * STORY.length)]; return say(s[0] + nm(p) + s[1] + s[2] + s[3]); },
  async riddle({ env, say, r }) { const [q, a] = RIDDLES[Math.floor(r() * RIDDLES.length)]; await env.state.set("riddle", { q, a, until: Date.now() + 3 * 60000 }, 240); return say("**Riddle:** " + q + "\nAnswer with `!solve ...`"); },
  async solve({ arg, env, me, nm, say }) {
    const st = await env.state.get("riddle"); if (!st || st.until < Date.now()) return say("No riddle right now. Get one with `!riddle`");
    const g = String(arg).toLowerCase().replace(/[^a-z ]/g, "").trim();
    if (!st.a.some(x => g === x || g === x.replace(/^(a|an|your) /, ""))) return say("Not quite, " + nm(me) + ". Think about it!");
    await env.state.del("riddle"); const paid = await env.addBananas(me.uid, 3); return say(nm(me) + " solved it! The answer is **" + st.a[0] + "**." + (paid ? " +3 🍌" : ""));
  },
  async wyr({ say, r }) { return say(WYR[Math.floor(r() * WYR.length)]); },
  async thisorthat({ say, r }) { return say(TOT[Math.floor(r() * TOT.length)]); },
  async addquote({ arg, env, me, nm, say }) {
    const t = String(arg).replace(/\s+/g, " ").trim().slice(0, 140); if (t.length < 3) return say("Type the quote after it, like `!addquote ooga booga forever`");
    if (env.hasBad && env.hasBad(t)) return say("That quote has a word we don't allow.");
    const q = (await env.state.get("quotes")) || []; q.push({ t, by: me.display || me.name }); await env.state.set("quotes", q.slice(-100), LONG); return say("Saved quote #" + Math.min(100, q.length) + " from " + nm(me) + ".");
  },
  async quote({ env, say, r }) { const q = (await env.state.get("quotes")) || []; if (!q.length) return say("“" + QUOTE_LINES[Math.floor(r() * QUOTE_LINES.length)] + "”\nSave your own with `!addquote`"); const x = q[Math.floor(r() * q.length)]; return say("“" + x.t + "”\n- " + x.by); },
  async quotes({ env, say }) { const q = (await env.state.get("quotes")) || []; return say(q.length ? q.length + (q.length === 1 ? " quote" : " quotes") + " saved. Get one with `!quote`" : "No quotes saved yet. Add one with `!addquote`"); },
  async animal({ say, r }) { const [a, f] = ANIMAL_FACTS[Math.floor(r() * ANIMAL_FACTS.length)]; return say("**" + a + "** " + f); },
  async gorilla({ say, r }) { return say(GORILLA_FACTS[Math.floor(r() * GORILLA_FACTS.length)]); },
  async sound({ env, say, r }) { const [s, a] = SOUNDS[Math.floor(r() * SOUNDS.length)]; await env.state.set("sound", { a, until: Date.now() + 60000 }, 90); return say("Who says **" + s + "**? Answer with `!itsa` and the animal."); },
  async itsa({ arg, env, me, nm, say }) { const st = await env.state.get("sound"); if (!st || st.until < Date.now()) return say("No sound to guess right now. Try `!sound`"); const g = String(arg).toLowerCase().replace(/^an? /, "").trim(); if (!st.a.includes(g)) return say("Nope! Try again."); await env.state.del("sound"); return say(nm(me) + " got it! It's a **" + st.a[0] + "**!"); }
};
BOT_LIST.animalbot.cmds.push(["!itsa", "Answer the sound, like !itsa cow"]);
async function botCount(text, env) {
  if (!env.bots.includes("countbot")) return [];
  const v = parseInt(text, 10), c = (await env.state.get("count")) || { n: 0, last: "" }, me = env.author;
  const say = t => [{ bot: "countbot", text: t }];
  if (v !== c.n + 1 || c.last === me.uid) {
    if (c.n === 0 && v !== 1) return [];
    const why = c.last === me.uid ? "counted twice in a row" : "said " + v + " instead of " + (c.n + 1);
    await env.state.set("count", { n: 0, last: "" }, LONG);
    return say("**" + (me.display || me.name) + "** " + why + ". The count was at **" + c.n + "**. Start again from **1**!");
  }
  await env.state.set("count", { n: v, last: me.uid, best: Math.max(c.best || 0, v) }, LONG);
  return v % 25 === 0 ? say("**" + v + "**! The troop is counting strong.") : [];
}
const BOT_IDS = Object.keys(BOT_LIST);
const DEFAULT_BOTS = ["yapbot", "funbot", "bananabot", "modbot"];
const BOT_CMD = {}; for (const [id, b] of Object.entries(BOT_LIST)) for (const [c] of b.cmds) BOT_CMD[c.slice(1)] = id;

const JOKES = [
  "Why don't gorillas use computers? They're scared of the mouse. 🐭",
  "What do you call a monkey that won't behave? A ba-NO-na. 🍌",
  "Why did the banana go to the doctor? It wasn't peeling well.",
  "What's a gorilla's favorite cookie? Chocolate chimp. 🍪",
  "Why can't you trust a tree? It seems shady. 🌳",
  "What do you call a sleeping dinosaur? A dino-snore. 🦖",
  "Why did the scarecrow win an award? He was outstanding in his field.",
  "What did one wall say to the other? I'll meet you at the corner.",
  "Why are ghosts bad liars? You can see right through them. 👻",
  "What do you call a fish with no eyes? A fsh. 🐟",
  "Why did the math book look sad? It had too many problems.",
  "What do monkeys wear to cook? Ape-rons. 👨‍🍳",
  "How do you make an octopus laugh? With ten-tickles. 🐙",
  "Why did the cookie go to the nurse? It felt crummy.",
  "What do you call a bear with no teeth? A gummy bear. 🧸",
  "Why can't a bicycle stand up by itself? It's two tired. 🚲",
  "What did the ocean say to the beach? Nothing, it just waved. 🌊",
  "Why did the gorilla bring a ladder to school? To get to high school.",
  "What's orange and sounds like a parrot? A carrot. 🥕",
  "Why do bananas wear sunscreen? So they don't peel. ☀️",
  "What kind of key opens a banana? A mon-key. 🔑",
  "Why was the computer cold? It left its Windows open. 🪟",
  "What do you call cheese that isn't yours? Nacho cheese. 🧀",
  "Why did the chicken join a band? It had the drumsticks. 🥁"
];
const FACTS = [
  "Gorillas share about 98% of their DNA with humans. 🦍",
  "A group of gorillas is called a troop (or a band).",
  "Gorillas mostly eat plants: leaves, stems, fruit and bamboo. 🌿",
  "Adult male gorillas are called silverbacks because of the silver hair on their backs.",
  "Gorillas build a fresh nest to sleep in almost every night.",
  "Octopuses have three hearts and blue blood. 🐙",
  "Sharks have been around longer than trees. 🦈",
  "Sea otters hold hands while they sleep so they don't drift apart. 🦦",
  "A group of flamingos is called a flamboyance. 🦩",
  "A day on Venus is longer than a year on Venus. 🪐",
  "Bananas are berries, but strawberries aren't. 🍌",
  "Honey never spoils. Archaeologists have found 3,000-year-old honey that was still good. 🍯",
  "Sloths can hold their breath longer than dolphins can, up to about 40 minutes. 🦥",
  "A blue whale's heart is about as big as a small car. 🐋",
  "Butterflies taste with their feet. 🦋",
  "Elephants can recognize themselves in a mirror. 🐘",
  "Koalas sleep up to 22 hours a day. 🐨",
  "Hummingbirds are the only birds that can fly backwards.",
  "Starfish don't have brains. ⭐",
  "Gentoo penguins give their partners pebbles to build nests. 🐧",
  "Every gorilla has a unique nose print, like a fingerprint.",
  "Your heart beats about 100,000 times every day. ❤️",
  "Owls can turn their heads about 270 degrees. 🦉",
  "Giraffes have the same number of neck bones as humans: seven. 🦒"
];
const EIGHT = ["Yes, definitely! ✅", "It is certain. 💯", "Without a doubt.", "Most likely. 👍", "Signs point to yes. 👉", "Ask again later. ⏳", "Better not tell you now. 🤐", "Can't say right now. 🔮", "Don't count on it. 🙅", "My sources say no. 📉", "Very doubtful. 🤔", "Outlook not so good. 🌧️", "Ooga says yes. 🦍", "Ooga says no. 🦍"];
const MONKE = ["Climb first, ask questions later. 🌳", "A banana a day keeps the boredom away. 🍌", "Never trust a floor. 🦍", "Every tree was once a tiny seed. Keep growing.", "Ooga booga is not just words. It is a lifestyle.", "The fastest monke is the one who never stops.", "Be the silverback you wish to see in the troop.", "If you fall, that just means you were climbing.", "Share your bananas and you'll never eat alone.", "Real monkes say gg win or lose."];
const COMPLIMENTS = ["is an absolute legend 🏆", "has the best vibes in the whole jungle 🌴", "is cooler than a frozen banana 🥶🍌", "makes this server 100% better 💯", "is a top-tier monke 🦍", "is the reason the troop smiles 😄", "climbs faster than anyone here 🌳", "is super kind and everyone knows it 💖"];
const TRIVIA = [
  ["What planet is known as the Red Planet?", ["mars"]], ["How many legs does a spider have?", ["8", "eight"]], ["What's the largest ocean on Earth?", ["pacific", "pacific ocean"]],
  ["What do bees make?", ["honey"]], ["How many days are in a leap year?", ["366"]], ["What's the tallest animal in the world?", ["giraffe", "giraffes"]],
  ["What color do you get when you mix blue and yellow?", ["green"]], ["What's the closest star to Earth?", ["sun", "the sun"]], ["How many continents are there?", ["7", "seven"]],
  ["What's frozen water called?", ["ice"]], ["Which animal is known as the King of the Jungle?", ["lion", "lions"]], ["How many sides does a hexagon have?", ["6", "six"]],
  ["What's the biggest planet in our solar system?", ["jupiter"]], ["What gas do plants take in from the air?", ["carbon dioxide", "co2"]], ["What's 7 times 8?", ["56", "fifty six", "fifty-six"]],
  ["What's the fastest land animal?", ["cheetah", "cheetahs"]], ["How many minutes are in an hour?", ["60", "sixty"]], ["Which fruit do monkeys love in cartoons?", ["banana", "bananas"]],
  ["What's the largest mammal on Earth?", ["blue whale", "whale"]], ["What do caterpillars turn into?", ["butterfly", "butterflies", "moth", "moths"]], ["How many colors are in a rainbow?", ["7", "seven"]],
  ["What's the capital of France?", ["paris"]], ["What's 12 + 15?", ["27", "twenty seven", "twenty-seven"]], ["Which planet has big rings around it?", ["saturn"]],
  ["What's a baby kangaroo called?", ["joey"]], ["How many hours are in a day?", ["24", "twenty four", "twenty-four"]], ["What's the main language spoken in Brazil?", ["portuguese"]],
  ["Which bird is a symbol of peace?", ["dove", "doves"]], ["What's the hardest natural material?", ["diamond", "diamonds"]], ["How many wheels does a tricycle have?", ["3", "three"]]
];
const BOT_RULES = ["Be kind. No bullying.", "Keep it clean: no swearing or rude pictures.", "Stay safe: never share your address, school, phone number or passwords.", "No spam.", "Be yourself: don't pretend to be someone else."];

const botPick = (list, r) => list[Math.floor(r() * list.length) % list.length];
const botNorm = t => String(t || "").toLowerCase().replace(/[^a-z0-9 ]+/g, "").replace(/\s+/g, " ").trim();
const botLevel = xp => Math.floor(Math.sqrt((xp || 0) / 3)) + 1;

// text: the message; env: {author:{uid,name,display}, bots:[ids], isMod, place:{name, members}, chan,
//   findUser(name)->profile|null, getProfile(uid), top(n)->[profiles], state.get(k), state.set(k,v,ttlSec), state.del(k),
//   addBananas(uid,n)->bool, transfer(fromUid,toUid,n)->{ok,msg}, rand()}
// returns [{bot, text}]
// bot replies start with words, not an emoji
function botPlain(t) { return String(t).replace(/^(?:[\p{Extended_Pictographic}\u2600-\u27BF]\uFE0F?\s*)+/u, "").replace(/\n(?:[\p{Extended_Pictographic}\u2600-\u27BF]\uFE0F?\s*)+/gu, "\n").replace(/[ \t]*(?!🍌)\p{Extended_Pictographic}\uFE0F?(?=[ \t]*(?:\n|$))/gu, ""); }
async function botRun(text, env) {
  if (/^\d{1,7}$/.test(String(text || "").trim())) return botCount(String(text).trim(), env);
  const m = /^!([a-z0-9]+)\b\s*([\s\S]*)$/i.exec(String(text || "").trim());
  if (!m) return [];
  const cmd = m[1].toLowerCase(), arg = m[2].trim().slice(0, 200), r = env.rand || Math.random;
  const bot = cmd === "help" ? "yapbot" : BOT_CMD[cmd];
  if (!bot || !env.bots.includes(bot)) return [];
  const me = env.author, nm = p => "**" + (p.display || p.name || "someone") + "**";
  const say = t => [{ bot, text: botPlain(t) }];
  const who = async () => { const mm = /@([A-Za-z0-9_]{2,16})/.exec(arg); return mm ? await env.findUser(mm[1]) : null; };
  if (EXTRA_CMDS[cmd]) return EXTRA_CMDS[cmd]({ arg, env, me, nm, say, who, r, bot, text });
  switch (cmd) {
    case "help": {
      const lines = env.bots.map(id => { const b = BOT_LIST[id]; return "**" + b.name + "**: " + b.cmds.map(c => "`" + c[0] + "`").join(" "); });
      return say("🤖 **Bot commands**\n" + lines.join("\n") + "\nTip: type `!` in the message box to see them all.");
    }
    case "ping": return say("🏓 Pong! All bots are awake.");
    case "roll": {
      const d = /^(\d{1,2})?d(\d{1,3})$/i.exec(arg.replace(/\s/g, "")) || (/^\d{1,3}$/.test(arg) ? [null, "1", arg] : null);
      const n = Math.min(10, Math.max(1, +(d && d[1]) || 1)), s = Math.min(100, Math.max(2, +(d && d[2]) || 6));
      const rolls = Array.from({ length: n }, () => 1 + Math.floor(r() * s));
      return say("🎲 " + nm(me) + " rolled " + (n > 1 ? rolls.join(" + ") + " = **" + rolls.reduce((a, b) => a + b, 0) + "**" : "**" + rolls[0] + "**") + " (" + n + "d" + s + ")");
    }
    case "flip": return say("🪙 " + nm(me) + " flipped a coin: **" + (r() < 0.5 ? "Heads" : "Tails") + "**!");
    case "8ball": return arg ? say("🎱 " + botPick(EIGHT, r)) : say("🎱 Ask me a question, like `!8ball will I win today?`");
    case "choose": {
      const opts = arg.split(/\s*(?:\||,|\bor\b)\s*/i).map(x => x.trim()).filter(Boolean).slice(0, 10);
      return opts.length < 2 ? say("🤔 Give me at least 2 things, like `!choose pizza | tacos`") : say("🤔 I pick... **" + botPick(opts, r) + "**!");
    }
    case "server": return say("🏠 **" + env.place.name + "**\n#" + env.chan + (env.place.members != null ? " · " + env.place.members + " members" : "") + " · bots: " + env.bots.map(id => BOT_LIST[id].name).join(", "));
    case "whois": {
      const p = (await who()) || me;
      return say("🪪 " + nm(p) + " (@" + p.name + ")\nLevel **" + botLevel(p.xp ?? p.bananas) + "** · " + (p.bananas || 0) + " 🍌" + (p.joined ? " · joined " + new Date(p.joined).toLocaleDateString("en-US", { month: "short", year: "numeric" }) : "") + (p.status ? "\n💬 " + String(p.status).slice(0, 80) : ""));
    }
    case "joke": return say("😂 " + botPick(JOKES, r));
    case "fact": return say("🧠 **Fact:** " + botPick(FACTS, r));
    case "monke": return say("🦍 *\"" + botPick(MONKE, r) + "\"*");
    case "rate": return arg ? say("📊 I rate **" + arg.slice(0, 60) + "** a **" + Math.floor(r() * 11) + "/10**!") : say("📊 What should I rate? Like `!rate bananas`");
    case "hug": { const p = await who(); return say(p ? "🤗 " + nm(me) + " gives " + nm(p) + " a big gorilla hug!" : "🤗 " + nm(me) + " hugs the whole troop!"); }
    case "compliment": { const p = (await who()) || me; return say("💖 " + nm(p) + " " + botPick(COMPLIMENTS, r)); }
    case "trivia": {
      const cur = await env.state.get("trivia");
      if (cur && cur.until > Date.now()) return say("❓ There's already a question: **" + cur.q + "**\nAnswer with `!answer ...`");
      const [q, a] = botPick(TRIVIA, r);
      await env.state.set("trivia", { q, a, until: Date.now() + 60000 }, 70);
      return say("❓ **Trivia time!** " + q + "\nFirst to type `!answer ...` in the next 60 seconds wins **5 🍌**!");
    }
    case "answer": {
      const cur = await env.state.get("trivia");
      if (!cur || cur.until < Date.now()) return say("❓ No trivia right now. Start one with `!trivia`");
      if (!arg) return say("❓ Type your answer after it, like `!answer mars`");
      if (!cur.a.includes(botNorm(arg))) return say("❌ Not quite, " + nm(me) + ". Keep trying!");
      await env.state.del("trivia");
      const paid = await env.addBananas(me.uid, 5);
      return say("🎉 " + nm(me) + " got it! The answer was **" + cur.a[0] + "**." + (paid ? " +5 🍌" : ""));
    }
    case "infection": case "run": case "tag": case "lava": {
      const now = Date.now(), K = "infect";
      let g = await env.state.get(K);
      const pn = u => "**" + ((g && g.names[u]) || "someone") + "**", list = a => a.map(pn).join(", ");
      const players = () => Object.keys(g.names), runners = () => players().filter(u => !g.lava.includes(u));
      if (g && g.until < now) {
        const surv = runners(), paid = players().length >= 3;
        await env.state.del(K);
        if (paid) for (const u of surv) { await env.addBananas(u, 5); if (env.stat) await env.stat(u, "surv"); }
        const end = players().length < 2 ? "⏰ That tag round ended. Nobody joined." : surv.length ? "⏰ Time's up! The lava didn't get " + list(surv) + ". Survivors win" + (paid ? " (+5 🍌 each)" : "") + "!" : "⏰ Time's up! The lava got everyone.";
        if (cmd !== "infection") return say(end + "\nStart a new round with `!infection`");
        g = null; const next = await botRun(text, env); return [{ bot, text: end }].concat(next);
      }
      if (cmd === "infection" && !g) {
        g = { host: me.uid, names: { [me.uid]: me.display || me.name || "someone" }, lava: [me.uid], started: now, until: now + 10 * 60000 };
        await env.state.set(K, g, 15 * 60);
        return say("🔥 **Infection!** " + pn(me.uid) + " is the lava monke.\nType `!run` to join. Lava monkes catch people with `!tag @name`. Last monke standing gets **10 🍌**, and anyone still running after 10 minutes gets **5 🍌**.");
      }
      if (!g) return say("🔥 No tag game right now. Start one with `!infection`");
      const left = Math.max(1, Math.ceil((g.until - now) / 60000));
      if (cmd === "infection" || cmd === "lava") return say("🔥 **Lava:** " + list(g.lava) + "\n🏃 **Running:** " + (runners().length ? list(runners()) : "nobody yet") + "\n" + left + " min left. Join with `!run`");
      if (cmd === "run") {
        if (g.names[me.uid]) return say(g.lava.includes(me.uid) ? "🔥 You're lava, " + nm(me) + "! Go tag someone with `!tag @name`" : "🏃 You're already running, " + nm(me) + "!");
        if (players().length >= 30) return say("🔥 This round is full. Wait for the next one!");
        g.names[me.uid] = me.display || me.name || "someone";
        await env.state.set(K, g, Math.ceil((g.until - now) / 1000) + 300);
        return say("🏃 " + nm(me) + " is running from the lava! " + runners().length + " running, " + g.lava.length + " lava.");
      }
      // tag
      if (!g.lava.includes(me.uid)) return say(g.names[me.uid] ? "🏃 You're not lava, " + nm(me) + ". Keep running!" : "🔥 You're not in this round. Join with `!run`");
      const p = await who();
      if (!p) return say("🔥 Tag someone who's running, like `!tag @name`");
      if (!g.names[p.uid]) return say("🔥 " + nm(p) + " isn't in this round.");
      if (g.lava.includes(p.uid)) return say("🔥 " + nm(p) + " is already lava!");
      g.lava.push(p.uid);
      if (env.stat) await env.stat(me.uid, "tags");
      if (!runners().length) {
        const paid = players().length >= 3 && now - g.started >= 60000;
        await env.state.del(K);
        if (paid) { await env.addBananas(p.uid, 10); if (env.stat) await env.stat(p.uid, "tagWins"); }
        return say("🔥 " + nm(me) + " tagged " + nm(p) + "! Everyone is lava. " + nm(p) + " was the last monke standing" + (paid ? " (+10 🍌)" : "") + ". GG!\nPlay again with `!infection`");
      }
      await env.state.set(K, g, Math.ceil((g.until - now) / 1000) + 300);
      return say("🔥 " + nm(me) + " tagged " + nm(p) + "! " + nm(p) + " is lava now. " + runners().length + " left: " + list(runners()));
    }
    case "bananas": { const p = (await who()) || me; return say("🍌 " + nm(p) + " has **" + (p.bananas || 0) + "** bananas."); }
    case "level": { const p = (await who()) || me, xp = p.xp ?? p.bananas ?? 0, lv = botLevel(xp); return say("⬆️ " + nm(p) + " is level **" + lv + "** (" + xp + " XP, " + (3 * lv * lv - xp) + " to go)"); }
    case "top": {
      const t = await env.top(5);
      return say(t.length ? "🏆 **Top bananas**\n" + t.map((p, i) => (i + 1) + "." + " " + nm(p) + ": " + (p.bananas || 0) + " 🍌").join("\n") : "🏆 Nobody has bananas yet!");
    }
    case "give": {
      const p = await who(), n = Math.floor(+((/(\d+)\s*$/.exec(arg) || [])[1] || 0));
      if (!p || !n) return say("🍌 Use it like `!give @name 10`");
      if (p.uid === me.uid) return say("🍌 You can't give bananas to yourself, silly!");
      if (n > 500) return say("🍌 You can give up to 500 bananas at a time.");
      const res = await env.transfer(me.uid, p.uid, n);
      return say(res.ok ? "🍌 " + nm(me) + " gave **" + n + "** bananas to " + nm(p) + "! How nice." : "🍌 " + res.msg);
    }
    case "rules": return say("📜 **Rules**\n" + BOT_RULES.map((x, i) => (i + 1) + ". " + x).join("\n"));
    case "report": return say("🚩 To report someone, right-click (or long-press) their message and pick **Report**. The owner will see it.");
    case "warn": {
      if (!env.isMod) return say("🛡️ Only mods and the owner can warn people.");
      const p = await who(); if (!p) return say("🛡️ Use it like `!warn @name please stop spamming`");
      const why = arg.replace(/@[A-Za-z0-9_]+/, "").trim().slice(0, 120);
      return say("⚠️ " + nm(p) + " has been warned by " + nm(me) + (why ? ": " + why.replace(/[.!?]+$/, "") + "." : ".") + " Please follow the rules!");
    }
  }
  return [];
}
function botWelcome(name, place) { return "Welcome to **" + place + "**, **" + name + "**! Type `!help` to see what the bots can do."; }
function botBirthday(name) { return "Happy birthday, **" + name + "**! 🎉 The whole troop hopes you have an awesome day! (+50 🍌 from the bots)"; }
function botGotw(name, place, reason, prize) { return "**" + name + "** is the Gorilla of the Week in **" + place + "**!" + (reason ? " “" + reason + "”" : "") + " Everyone say GG!" + (prize ? " (+100 🍌)" : ""); }
function botSpamWarn(name) { return "**" + name + "**, slow down please. No spamming."; }

{ BOT_LIST, BOT_IDS, BOT_CATS, DEFAULT_BOTS, botRun, botWelcome, botSpamWarn, botBirthday, botGotw };

/* ===== lib/rules.js ===== */
// Who can read and write what. Every database request goes through these checks on the server.

const BUILTIN_MAPS = ["forest", "canyon", "caves", "mountains", "city", "clouds", "beach", "basement"];
const BUILTIN_FLAGS = { rules: { rules: true }, announcements: { ann: true } };
const PERMS = ["manageMessages", "timeout", "slowmode", "announce"];
const SHARED = ["reacts", "votes", "threadCount", "threadLast", "flags"];
const CE_RE = /^data:image\/(png|webp|gif|jpeg);base64,[A-Za-z0-9+/=]+$/;
const NAME_RE = /^[A-Za-z0-9_]{3,16}$/;

/* ---------- per-request context (caches lookups) ---------- */
function makeCtx(uid) {
  const cache = new Map();
  const ctx = {
    uid,
    async doc(path) { if (!cache.has(path)) cache.set(path, getDoc(path)); return cache.get(path); },
    prime(path, data) { cache.set(path, Promise.resolve(data)); },
    async meta() {
      if (!ctx._meta) ctx._meta = getDocs(["meta/owner", "meta/roles", "meta/bans", "mod/timeouts", "mod/slow"]).then(([o, r, b, t, s]) => {
        ["meta/owner", "meta/roles", "meta/bans", "mod/timeouts", "mod/slow"].forEach((p, i) => cache.set(p, Promise.resolve([o, r, b, t, s][i])));
        return { owner: o && o.uid, roles: r || { list: [], members: {} }, bans: (b && b.ids) || [], timeouts: t || {}, slow: s || {} };
      });
      return ctx._meta;
    },
    async isOwner(u = uid) { return (await ctx.meta()).owner === u; },
    async can(perm, u = uid) {
      const m = await ctx.meta(); if (m.owner === u) return true;
      const ids = (m.roles.members || {})[u] || [];
      return (m.roles.list || []).some(r => ids.includes(r.id) && r.perms && r.perms[perm]);
    },
    async hasRole(u = uid) { const m = await ctx.meta(); return m.owner === u || ((m.roles.members || {})[u] || []).length > 0; },
    async timedOut(u = uid) { const m = await ctx.meta(); return m.owner !== u && (+m.timeouts[u] || 0) > Date.now(); },
    async siteBanned(u = uid) { const m = await ctx.meta(); return m.owner !== u && m.bans.includes(u); },
    async server(docId) { return ctx.doc("servers/" + docId); },
    async group(gid) { return ctx.doc("gdmmeta/" + gid); }
  };
  return ctx;
}

/* ---------- channels ---------- */
// key looks like "forest.general" or "s-<serverDocId>.general"
async function chanInfo(ctx, key) {
  const i = key.indexOf("."); if (i < 1) return null;
  const mapId = key.slice(0, i), chan = key.slice(i + 1);
  if (mapId.startsWith("s-")) {
    const srv = await ctx.server(mapId.slice(2)); if (!srv) return null;
    const c = (srv.chans || []).find(x => x.id === chan);
    return { mapId, chan, server: srv, ann: !!(c && c.ann), rules: false, exists: !!c, see: (c && c.see) || "" };
  }
  if (!BUILTIN_MAPS.includes(mapId)) return null;
  const cfg = await ctx.doc("mapcfg/" + mapId);
  return { mapId, chan, builtin: true, cfg, ann: !!(BUILTIN_FLAGS[chan] || {}).ann, rules: !!(BUILTIN_FLAGS[chan] || {}).rules, exists: true };
}
async function serverVisible(ctx, s) {
  if (!s) return false;
  if (s.owner === ctx.uid || await ctx.isOwner()) return true;
  if ((s.bans || []).includes(ctx.uid)) return false;
  return !s.private || (s.members || []).includes(ctx.uid);
}
async function canReadChannel(ctx, key) {
  const ci = await chanInfo(ctx, key); if (!ci) return false;
  if (ci.server) {
    if (!(await serverVisible(ctx, ci.server))) return false;
    if (!ci.see) return true;
    if (ci.server.owner === ctx.uid || await ctx.isOwner() || await ctx.can("manageMessages")) return true;
    if (ci.see.startsWith("tag:")) { const p = await ctx.doc("profiles/" + ctx.uid); const tags = p && p.srvTags && p.srvTags[ci.mapId.slice(2)]; return Array.isArray(tags) && tags.includes(ci.see.slice(4)); }
    return false;
  }
  if (ci.cfg && (ci.cfg.bans || []).includes(ctx.uid) && !(await ctx.isOwner())) return false;
  return true;
}
const inPair = (ctx, pair) => pair.split("~").includes(ctx.uid);
async function inGroup(ctx, gid) { const g = await ctx.group(gid); return !!(g && (g.members || []).includes(ctx.uid)); }
async function canSeeThread(ctx, t) {
  if (t.startsWith("dm~")) return inPair(ctx, t.slice(3));
  if (t.startsWith("gdm~")) return inGroup(ctx, t.split("~")[1]);
  return canReadChannel(ctx, t.split("~")[0]);
}
const convoKeyOfMsgPath = seg => seg[0] === "ch" ? seg[1] : seg[0] === "dm" ? "dm~" + seg[1] : seg[0] === "gdm" ? "gdm~" + seg[1] : null;

/* ---------- reading ---------- */
// Returns the data the user may see (maybe trimmed), or null if they can't see it.
async function readable(ctx, path, data) {
  const seg = path.split("/"), top = seg[0];
  switch (top) {
    case "meta": case "mapcfg": case "mod": case "profiles": case "emoji": case "images": case "stickers": return data;
    case "sounds": return data;
    case "inbox": return seg[1] === ctx.uid ? data : null;
    case "events": {
      if (!data) return data;
      const mid = String(data.mapId || "");
      if (mid.startsWith("s-")) return (await serverVisible(ctx, await ctx.server(mid.slice(2)))) ? data : null;
      return BUILTIN_MAPS.includes(mid) ? data : null;
    }
    case "servers": {
      if (!data) return data;
      if (!(await serverVisible(ctx, data))) return null;
      return data;
    }
    case "ch": return (await canReadChannel(ctx, seg[1])) ? data : null;
    case "dm": return inPair(ctx, seg[1]) ? data : null;
    case "gdmmeta": return data && (data.members || []).includes(ctx.uid) ? data : null;
    case "gdm": return (await inGroup(ctx, seg[1])) ? data : null;
    case "th": return (await canSeeThread(ctx, seg[1])) ? data : null;
    case "last": {
      const k = seg[1];
      if (k.startsWith("dm~")) return inPair(ctx, k.slice(3)) ? data : null;
      if (k.startsWith("gdm~")) return (await inGroup(ctx, k.slice(4))) ? data : null;
      return (await canReadChannel(ctx, k)) ? data : null;
    }
    case "dmidx": return seg[1] === ctx.uid ? data : null;
    case "freq": return seg[1] === ctx.uid ? data : null;
    case "gifts": return seg[1] === ctx.uid ? data : null;
    case "bank": return seg[1] === ctx.uid ? data : null;
    case "invites": return data;
    case "gotw": { if (!data) return data; if (seg[1].startsWith("s-")) return (await serverVisible(ctx, await ctx.server(seg[1].slice(2)))) ? data : null; return data; }
    case "sreports": { const srv = await ctx.server(seg[1]); return srv && (srv.owner === ctx.uid || await ctx.isOwner()) ? data : null; }
    case "codes": {
      if (!data || !(data.until > Date.now())) return null;
      const w = String(data.where || "");
      if (w.startsWith("s-")) return (await serverVisible(ctx, await ctx.server(w.slice(2)))) ? data : null;
      return w === "global" ? data : null;
    }
    case "reports": return (seg[1] === ctx.uid || await ctx.isOwner()) ? data : null;
    case "modlog": {
      if (seg[1] === "global") return (await ctx.isOwner()) || (await ctx.can("manageMessages")) || (await ctx.can("timeout")) ? data : null;
      if (String(seg[1]).startsWith("s-")) { const srv = await ctx.server(seg[1].slice(2)); return srv && (srv.owner === ctx.uid || await ctx.isOwner()) ? data : null; }
      return null;
    }
    case "data": return seg[2] === ctx.uid ? data : null;
    default: return null;
  }
}
// Can the user list this collection at all? (Individual docs are still filtered by readable.)
async function canListCollection(ctx, colPath) {
  const seg = colPath.split("/");
  if (seg.length === 1) return ["meta", "mapcfg", "mod", "profiles", "emoji", "servers", "gdmmeta", "last", "reports", "dmidx", "events", "sounds", "codes", "gotw", "stickers"].includes(seg[0]);
  if (seg.length === 3 && seg[2] === "m") {
    if (seg[0] === "ch") return canReadChannel(ctx, seg[1]);
    if (seg[0] === "dm") return inPair(ctx, seg[1]);
    if (seg[0] === "gdm") return inGroup(ctx, seg[1]);
    if (seg[0] === "th") return canSeeThread(ctx, seg[1]);
  }
  return false;
}


/* ---------- phone / computer notifications ---------- */
function pushPreview(m) { return m.text ? censor(str(m.text, 140)) : m.img ? "Sent a picture" : m.sticker ? "Sent a sticker" : m.voice ? "Sent a voice message" : m.poll ? "Made a poll: " + censor(str(m.poll.q, 80)) : "Sent a message"; }
async function authorName(ctx, uid) { const p = await ctx.doc("profiles/" + uid); return str((p && (p.display || p.name)) || "Someone", 32); }
function addPush(ctx, to, payload) { (ctx.pushes = ctx.pushes || []).push({ uid: to, payload }); }
async function queueMsgPush(ctx, top, key, m, uid) {
  const name = await authorName(ctx, uid), k = top === "dm" ? "dm~" + key : "gdm~" + key;
  const base = { body: pushPreview(m), tag: k, url: "/?go=" + encodeURIComponent(k) };
  if (top === "dm") {
    const other = key.split("~").find(x => x !== uid);
    if (other) addPush(ctx, other, Object.assign({ title: name }, base));
  } else {
    const g = await ctx.group(key); if (!g) return;
    const gname = str(g.name, 32) || "your group";
    (g.members || []).filter(u => u !== uid).slice(0, 6).forEach(u => addPush(ctx, u, Object.assign({ title: name + " in " + gname }, base)));
  }
}
async function queuePingPush(ctx, to, item, uid) {
  if (!item || to === uid) return;
  const k = String(item.k || "");
  if (!/^[A-Za-z0-9_.~:-]{1,200}$/.test(k) || k.startsWith("dm~") || k.startsWith("gdm~")) return;
  const chanKey = k.startsWith("th~") ? k.slice(3).split("~")[0] : k;
  if (!(await canReadChannel(makeCtx(to), chanKey))) return;
  const name = await authorName(ctx, uid), ch = chanKey.split(".").slice(1).join(".") || "chat";
  addPush(ctx, to, { title: name + (item.kind === "reply" ? " replied in #" : " pinged you in #") + ch, body: item.text || "", tag: k, url: "/?go=" + encodeURIComponent(k) });
}
/* ---------- helper bots ---------- */
function serverBots(srv) { return srv ? (Array.isArray(srv.bots) ? srv.bots.filter(b => BOT_IDS.includes(b)) : DEFAULT_BOTS.slice()) : DEFAULT_BOTS.slice(); }
const MAP_NAMES = { forest: "Forest", canyon: "Canyon", caves: "Caves", mountains: "Mountains", city: "City", clouds: "Clouds", beach: "Beach", basement: "Basement" };
// banana changes from bots go into a "bank" box that the person's own app collects, so nothing gets overwritten
async function bankAdd(ctx, extra, u, n, why, xp) {
  const path = "bank/" + u, cur = (await ctx.doc(path)) || { items: [] };
  const next = { items: (cur.items || []).slice(-40).concat({ id: randomId(10), n, why: String(why || "").slice(0, 40), xp: !!xp }) };
  ctx.prime(path, next);
  const i = extra.findIndex(x => x.path === path); if (i > -1) extra.splice(i, 1);
  extra.push({ path, data: next });
}
// mod log: modlog/global (site mods) and modlog/s-<server> (that server's owner). Only the server writes it.
async function modLogAdd(ctx, extra, scope, entry) {
  const path = "modlog/" + scope, i = extra.findIndex(x => x.path === path);
  const cur = i > -1 ? extra[i].data : ((await ctx.doc(path)) || { items: [] });
  const e = { id: randomId(10), by: ctx.uid, ts: Date.now(), act: str(entry.act, 20), who: str(entry.who, 80), text: str(entry.text, 140), where: str(entry.where, 60) };
  const next = { items: ((cur && cur.items) || []).slice(-199).concat(e) };
  ctx.prime(path, next); if (i > -1) extra.splice(i, 1); extra.push({ path, data: next });
}
const GAMES = ["gtag", "amongus", "minecraft", "roblox", "fortnite", "capuchin", "animalco", "recroom", "beatsaber", "other"];
const SERVER_BGS = ["pines","lava","forest","canopy","mountains","canyon","caves","beach","clouds","city","basement","m-lava","m-stars","m-rain","m-forest","m-clouds","m-fireflies"];
const SERVER_CATS = ["infection", "casual", "comp", "hunt", "fanart", "hangout", "cosmetics", "other"];
function botMsg(key, bot, text, ts) { return { path: "ch/" + key + "/m/" + randomId(20), data: { uid: "bot:" + bot, ts, text: String(text).slice(0, 1500), reacts: {}, bot: 1 } }; }
async function botExtras(ctx, key, ci, msg, uid) {
  const bots = ci.server ? serverBots(ci.server) : DEFAULT_BOTS.slice();
  const extra = []; if (!bots.length) return extra;
  const text = String(msg.text || "");
  const getP = async u => { const p = await ctx.doc("profiles/" + u); return p ? Object.assign({ uid: u }, p) : null; };
  const me = (await getP(uid)) || { uid, name: "someone" };
  const isCount = bots.includes("countbot") && /^\d{1,7}$/.test(text.trim());
  // ModBot: warn people who post the same thing over and over
  if (bots.includes("modbot") && !text.startsWith("!") && !isCount) {
    const sk = "spam:" + uid + ":" + key, prev = await cmd("GET", sk);
    let st = { t: "", n: 0 }; try { if (prev) st = JSON.parse(prev); } catch (e) {}
    const norm = text.toLowerCase().trim();
    st = norm && norm === st.t ? { t: norm, n: st.n + 1 } : { t: norm, n: 1 };
    await cmd("SET", sk, JSON.stringify(st), "EX", 40);
    if (st.n >= 3 && await cmd("SET", "spamwarn:" + uid + ":" + key, "1", "EX", 60, "NX")) extra.push(botMsg(key, "modbot", botSpamWarn(me.display || me.name), msg.ts + 1));
    return extra;
  }
  if (!text.startsWith("!") && !isCount) return extra;
  const isMod = (await ctx.can("timeout")) || (await ctx.can("manageMessages")) || !!(ci.server && ci.server.owner === uid);
  const env = {
    author: me, bots, isMod, chan: ci.chan,
    place: { name: ci.server ? String(ci.server.name || "this server") : (MAP_NAMES[ci.mapId] || ci.mapId), members: ci.server ? (ci.server.private ? (ci.server.members || []).length + 1 : null) : null },
    findUser: async n => { const u = await cmd("GET", "name:" + String(n).toLowerCase()); return u ? getP(u) : null; },
    top: async n => (await listDocs("profiles")).map(d => Object.assign({ uid: d.id }, d.data)).filter(p => p.name).sort((a, b) => (b.bananas || 0) - (a.bananas || 0)).slice(0, n),
    state: {
      get: async k => { const v = await cmd("GET", "botst:" + k + ":" + key); try { return v ? JSON.parse(v) : null; } catch (e) { return null; } },
      set: (k, v, ttl) => cmd("SET", "botst:" + k + ":" + key, JSON.stringify(v), "EX", ttl || 120),
      del: k => cmd("DEL", "botst:" + k + ":" + key)
    },
    addBananas: async (u, n) => { await bankAdd(ctx, extra, u, n, "trivia", true); return true; },
    transfer: async (a, b, n) => {
      const pa = await getP(a), pb = await getP(b);
      if (!pb) return { ok: false, msg: "I can't find that gorilla." };
      if ((pa && pa.bananas || 0) < n) return { ok: false, msg: "You only have " + ((pa && pa.bananas) || 0) + " bananas." };
      if (!(await cmd("SET", "give:" + a, "1", "EX", 10, "NX"))) return { ok: false, msg: "Wait a few seconds before giving again." };
      await bankAdd(ctx, extra, a, -n, "gave bananas"); await bankAdd(ctx, extra, b, n, "got bananas");
      return { ok: true };
    },
    stat: async (u, k) => { await bankAdd(ctx, extra, u, 0, "stat:" + String(k).slice(0, 12)); },
    hasBad,
    rand: Math.random
  };
  if (!isCount && !(await cmd("SET", "botrl:" + uid, "1", "PX", 1000, "NX"))) return extra; // one command a second per person
  const out = await botRun(text, env);
  if (env.isMod && /^!warn\b/i.test(text) && out.length && /has been warned/.test(out[0].text)) {
    const mm = /@([A-Za-z0-9_]{2,16})/.exec(text), who = mm ? await env.findUser(mm[1]) : null;
    if (who) await modLogAdd(ctx, extra, key.startsWith("s-") ? key.split(".")[0] : "global", { act: "warn", who: who.uid, text: text.replace(/^!warn\s*@\S+\s*/i, ""), where: key });
  }
  out.slice(0, 3).forEach((r, i) => extra.push(botMsg(key, r.bot, r.text, msg.ts + 1 + i)));
  return extra;
}

/* ---------- writing ---------- */
const deny = msg => { throw new Fail(403, "denied", msg || "You can't do that."); };
const str = (v, max) => typeof v === "string" ? v.slice(0, max) : "";
function changedKeys(a, b) {
  const keys = new Set([...Object.keys(a || {}), ...Object.keys(b || {})]);
  return [...keys].filter(k => JSON.stringify((a || {})[k]) !== JSON.stringify((b || {})[k]));
}
// Only my own entry may change inside reactions / votes.
function onlyMineChanged(ctx, before, after) {
  const vb = before.votes || {}, va = after.votes || {};
  for (const k of new Set([...Object.keys(vb), ...Object.keys(va)])) if (k !== ctx.uid && JSON.stringify(vb[k]) !== JSON.stringify(va[k])) return false;
  const fb = before.flags || {}, fa = after.flags || {};
  for (const k of new Set([...Object.keys(fb), ...Object.keys(fa)])) if (k !== ctx.uid && !!fb[k] !== !!fa[k]) return false;
  const rb = before.reacts || {}, ra = after.reacts || {};
  for (const e of new Set([...Object.keys(rb), ...Object.keys(ra)])) {
    const x = new Set(rb[e] || []), y = new Set(ra[e] || []);
    for (const u of new Set([...x, ...y])) if (u !== ctx.uid && x.has(u) !== y.has(u)) return false;
  }
  return true;
}
function cleanMessage(m) {
  const o = Object.assign({}, m);
  if ("text" in o) o.text = censor(str(o.text, 600));
  if (o.poll) o.poll = { q: censor(str(o.poll.q, 120)), opts: (Array.isArray(o.poll.opts) ? o.poll.opts : []).slice(0, 6).map(x => censor(str(x, 60))), closed: !!o.poll.closed };
  if (o.reply) o.reply = { id: str(o.reply.id, 60), uid: str(o.reply.uid, 80), text: censor(str(o.reply.text, 90)) };
  if (o.sticker != null) o.sticker = str(o.sticker, 20);
  if (o.img != null) o.img = str(o.img, 64);
  if (o.voice != null) {
    const v = o.voice, d = v && typeof v.data === "string" ? v.data : "";
    if (d.length <= 160000 && /^data:audio\/(webm|ogg|mp4|mpeg|aac|x-m4a|wav)(;[a-z0-9=.;-]*)?;base64,[A-Za-z0-9+/=]+$/i.test(d)) o.voice = { data: d, dur: Math.max(1, Math.min(31, Math.round(+v.dur || 1))) };
    else delete o.voice;
  }
  delete o.bot;
  if (o.cst != null) { const HEX = /^[0-9a-f]{32}$/, c = o.cst; o.cst = c && HEX.test(c.id || "") ? { id: c.id, still: HEX.test(c.still || "") ? c.still : c.id, gif: !!c.gif, anim: !!c.anim } : undefined; if (!o.cst) delete o.cst; }
  if (o.flags != null) { const f = {}; Object.entries(o.flags && typeof o.flags === "object" ? o.flags : {}).slice(0, 50).forEach(([k, v]) => { if (v === true && /^[A-Za-z0-9_-]{1,80}$/.test(k)) f[k] = true; }); o.flags = f; }
  if (o.cleared != null) o.cleared = !!o.cleared;
  if (o.fwd != null) { const f = o.fwd; o.fwd = f && typeof f === "object" ? { from: str(f.from, 80), where: censor(str(f.where, 40)) } : null; if (!o.fwd) delete o.fwd; }
  return o;
}

// Decide whether a write is allowed. Returns {after, extra:[...more writes], skip?}.
async function checkWrite(ctx, op, path, before, incoming) {
  const seg = path.split("/"), top = seg[0], uid = ctx.uid;
  let after = op === "delete" ? null : op === "update" ? deepMerge(before || {}, incoming || {}) : (incoming || {});
  const extra = [];
  const owner = await ctx.isOwner();
  if (await ctx.siteBanned() && !["data", "reports"].includes(top) && !(top === "profiles" && seg[1] === uid)) deny("You've been banned from Gorilla Yapps.");

  switch (top) {
    case "meta":
      if (seg[1] === "owner") deny("The owner can't be changed.");
      if (!owner) deny("Only the owner can change that.");
      if (seg[1] === "bans") {
        const b = new Set((before && before.ids) || []), a = new Set((after && after.ids) || []);
        for (const u of a) if (!b.has(u)) await modLogAdd(ctx, extra, "global", { act: "ban", who: u });
        for (const u of b) if (!a.has(u)) await modLogAdd(ctx, extra, "global", { act: "unban", who: u });
      }
      break;
    case "modlog": deny("The mod log is written by the server.");
    case "mapcfg":
      if (!owner) deny("Only the owner can change map settings.");
      break;
    case "mod": {
      if (seg[1] === "slow" && !(await ctx.can("slowmode"))) deny("You need the slow mode power.");
      if (seg[1] === "timeouts") {
        if (!(await ctx.can("timeout"))) deny("You need the timeout power.");
        const m = await ctx.meta();
        if (after && m.owner && after[m.owner]) deny("The owner can't be timed out.");
        const b = before || {}, a = after || {}, now = Date.now();
        for (const u of new Set([...Object.keys(b), ...Object.keys(a)])) {
          const was = (+b[u] || 0) > now, is = (+a[u] || 0) > now;
          if (is && (+a[u] || 0) !== (+b[u] || 0)) await modLogAdd(ctx, extra, "global", { act: "timeout", who: u, text: Math.round(((+a[u]) - now) / 60000) + " min" });
          else if (was && !is) await modLogAdd(ctx, extra, "global", { act: "untimeout", who: u });
        }
      }
      if (!["slow", "timeouts"].includes(seg[1])) deny();
      break;
    }
    case "stickers": { // custom stickers: stickers/<mapId> = {list:[{name, img:{id,still,gif,anim}}]}
      const mid = seg[1];
      if (seg.length !== 2) deny();
      if (mid.startsWith("s-")) { const sv = await ctx.server(mid.slice(2)); if (!sv || (sv.owner !== uid && !owner)) deny("Only the server owner can change its stickers."); }
      else if (!owner) deny("Only the owner can change map stickers.");
      if (after) {
        const HEX = /^[0-9a-f]{32}$/;
        const list = Array.isArray(after.list) ? after.list : [];
        if (list.length > 20) deny("Up to 20 stickers per server.");
        after = { list: list.map(x => ({ name: str(x && x.name, 18), by: str(x && x.by, 80), img: x && x.img && HEX.test(x.img.id || "") ? { id: x.img.id, still: HEX.test(x.img.still || "") ? x.img.still : x.img.id, gif: !!x.img.gif, anim: !!x.img.anim, ts: +x.img.ts || Date.now() } : null })).filter(x => x.img && /^[a-z0-9_]{2,18}$/.test(x.name) && !hasBad(x.name)) };
      }
      break;
    }
    case "emoji": {
      const mid = seg[1];
      if (mid.startsWith("s-")) { const s = await ctx.server(mid.slice(2)); if (!s || (s.owner !== uid && !owner)) deny("Only the server owner can change its emojis."); }
      else if (!owner) deny("Only the owner can change map emojis.");
      if (after) {
        const list = Array.isArray(after.list) ? after.list : [];
        if (list.length > 24) deny("Up to 24 emojis per server.");
        after = { list: list.map(e => ({ name: str(e.name, 24), data: str(e.data, 20000), by: str(e.by, 80) })).filter(e => /^[a-z0-9_]{2,24}$/.test(e.name) && CE_RE.test(e.data) && !hasBad(e.name)) };
      }
      break;
    }
    case "profiles": {
      if (seg[1] !== uid && owner && op === "update" && before && incoming && Object.keys(incoming).length && Object.keys(incoming).every(k => ["avatar", "banner"].includes(k) && incoming[k] === null)) {
        return { after, extra }; // the owner taking down someone's picture
      }
      if (seg[1] !== uid && !(op === "delete" && owner)) deny("You can only change your own profile.");
      if (after) for (const k of ["avatar", "banner"]) {
        const m = after[k];
        if (m == null) continue;
        if (typeof m !== "object" || !/^[0-9a-f]{32}$/.test(m.id || "") || (m.still && !/^[0-9a-f]{32}$/.test(m.still))) deny("That picture isn't valid.");
        after[k] = { id: m.id, still: m.still || m.id, gif: !!m.gif, anim: !!m.anim, ts: +m.ts || Date.now() };
      }
      if (after && after.activity != null) {
        const a = after.activity;
        if (!a || typeof a !== "object" || !["playing", "listening", "watching", "building", "chilling"].includes(a.type) || !str(a.text, 40).trim()) after.activity = null;
        else {
          if (hasBad(a.text)) deny("Your activity has a word we don't allow.");
          const o = { type: a.type, text: str(a.text, 40).trim(), until: +a.until || 0 };
          if (GAMES.includes(a.game)) {
            const num = v => Math.max(0, Math.min(99, Math.round(+v || 0)));
            o.game = a.game; o.mode = str(a.mode, 24); o.map = str(a.map, 24); o.code = String(a.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
            o.n = num(a.n); o.max = num(a.max); o.since = +a.since || Date.now(); o.detail = str(a.detail, 40).trim();
            if (hasBad(o.code) || hasBad(o.detail) || hasBad(o.mode) || hasBad(o.map)) deny("Your activity has a word we don't allow.");
          }
          after.activity = o;
        }
      }
      if (after) {
        const idOk = v => typeof v === "string" && /^[a-z0-9-]{0,24}$/.test(v);
        for (const k of ["acc", "effect", "hat", "face", "pattern", "nameColor", "deco", "bannerPreset", "avAnim"]) if (after[k] != null && !idOk(after[k])) after[k] = "";
        if (after.tagSrv != null) after.tagSrv = typeof after.tagSrv === "string" && /^[A-Za-z0-9_-]{1,40}$/.test(after.tagSrv) ? after.tagSrv : "";
        if (after.srvJoined != null) after.srvJoined = [...new Set((Array.isArray(after.srvJoined) ? after.srvJoined : []).filter(x => typeof x === "string" && /^[A-Za-z0-9_-]{1,40}$/.test(x)))].slice(0, 100);
        if (after.seen != null) after.seen = Math.max(0, Math.min(Date.now() + 60000, Math.round(+after.seen || 0)));
        if (after.hideSeen != null) after.hideSeen = !!after.hideSeen;
        if (after.stats != null) { const st = {}; for (const k of ["tags", "tagWins", "surv", "codes", "rounds"]) st[k] = Math.max(0, Math.min(1e6, Math.round(+((after.stats || {})[k]) || 0))); after.stats = st; }
        if (after.lvClaimed != null) after.lvClaimed = (Array.isArray(after.lvClaimed) ? after.lvClaimed : []).filter(n => Number.isInteger(n) && n > 0 && n <= 100).slice(0, 30);
        if (after.quests != null) { const q = after.quests; after.quests = q && typeof q === "object" && JSON.stringify(q).length < 1500 ? q : null; }
        if (after.outfits != null) {
          const F = ["hat", "face", "acc", "pattern", "nameColor", "deco", "effect", "fur"];
          after.outfits = (Array.isArray(after.outfits) ? after.outfits : []).slice(0, 3).map(o => {
            const r = { name: str(o && o.name, 20) };
            if (hasBad(r.name)) r.name = "Outfit";
            for (const f of F) if (o && o[f] != null) r[f] = f === "fur" ? str(o[f], 40) : (idOk(o[f]) ? o[f] : "");
            return r;
          });
        }
      }
      if (after) {
        if (after.bday != null) after.bday = /^(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/.test(after.bday) ? after.bday : "";
        if (after.nicks != null) {
          const o = {};
          for (const [k, v] of Object.entries(after.nicks && typeof after.nicks === "object" ? after.nicks : {}).slice(0, 40)) {
            const n = str(v, 24).replace(/\s+/g, " ").trim();
            if (!/^[A-Za-z0-9_-]{1,40}$/.test(k) || !n) continue;
            if (hasBad(n)) deny("That nickname has a word we don't allow.");
            o[k] = n;
          }
          after.nicks = o;
        }
        const invName = after.invitedName; delete after.invitedName;
        if (!before && seg[1] === uid && typeof invName === "string" && /^[A-Za-z0-9_]{3,16}$/.test(invName)) {
          const inv = await cmd("GET", "name:" + invName.toLowerCase());
          if (inv && inv !== uid) {
            const idoc = (await ctx.doc("invites/" + inv)) || { count: 0, list: [] };
            const list = Array.isArray(idoc.list) ? idoc.list : [];
            if (!list.includes(uid) && (idoc.count || 0) < 50) {
              after.invitedBy = inv;
              extra.push({ path: "invites/" + inv, data: { count: (idoc.count || 0) + 1, list: list.concat(uid).slice(-50), last: Date.now() } });
              await bankAdd(ctx, extra, inv, 25, "invite");
              await bankAdd(ctx, extra, uid, 25, "invited");
            }
          }
        } else if (before) after.invitedBy = before.invitedBy || null;
        const party = incoming && incoming.bdayParty; delete after.bdayParty;
        if (party && seg[1] === uid) {
          const d = String(party), y = +d.slice(0, 4);
          const near = Math.abs(Date.parse(d + "T12:00:00Z") - Date.now()) < 40 * 3600e3;
          if (/^\d{4}-\d{2}-\d{2}$/.test(d) && after.bday && d.slice(5) === after.bday && near && (before && before.bdayYear) !== y) {
            after.bdayYear = y;
            extra.push(botMsg("forest.general", "yapbot", botBirthday(after.display || after.name || "someone"), Date.now()));
            await bankAdd(ctx, extra, uid, 50, "birthday", false);
          } else if (before && before.bdayYear) after.bdayYear = before.bdayYear;
        } else if (op !== "delete" && before) after.bdayYear = before.bdayYear || after.bdayYear || 0;
      }
      if (after && after.srvTags != null) {
        const o = {};
        if (after.srvTags && typeof after.srvTags === "object") Object.entries(after.srvTags).slice(0, 40).forEach(([k, v]) => { if (/^[A-Za-z0-9_-]{1,80}$/.test(k) && Array.isArray(v)) o[k] = v.map(t => str(t, 20)).filter(Boolean).slice(0, 8); });
        after.srvTags = o;
      }
      if (after && after.theme != null && !(Array.isArray(after.theme) && after.theme.length === 2 && after.theme.every(c => /^#[0-9a-f]{6}$/i.test(c)))) delete after.theme;
      if (after) {
        if (!NAME_RE.test(after.name || "")) deny("Usernames need 3 to 16 letters, numbers or underscores.");
        if (hasBad(after.name) || hasBad(after.display) || hasBad(after.status) || hasBad(after.bio)) deny("Something in your profile has a word we don't allow.");
        after.display = str(after.display, 32); after.status = str(after.status, 40); after.bio = str(after.bio, 160);
        after.nameLower = after.name.toLowerCase();
        const holder = await cmd("GET", "name:" + after.nameLower);
        if (holder && holder !== uid) deny("Another gorilla already has that name. Try a different one.");
        extra.push({ redis: ["SET", "name:" + after.nameLower, uid] });
        if (before && before.nameLower && before.nameLower !== after.nameLower) extra.push({ redis: ["DEL", "name:" + before.nameLower] });
      } else if (before && before.nameLower) extra.push({ redis: ["DEL", "name:" + before.nameLower] });
      break;
    }
    case "servers": {
      if (!before) {
        if (!after || after.owner !== uid) deny("New servers must belong to you.");
        if (!str(after.name, 32) || hasBad(after.name)) deny("Pick a server name without bad words.");
      } else if (before.owner === uid || owner) {
        if (after && after.owner !== before.owner) deny("The server owner can't be changed.");
      } else {
        // Anyone else may only remove themselves (leave).
        const ck = changedKeys(before, after || {});
        if (!after || ck.some(k => k !== "members")) deny("Only the server owner can change that.");
        const b = new Set(before.members || []), a = new Set(after.members || []);
        if (a.has(uid) || !b.has(uid) || a.size !== b.size - 1) deny("You can only leave a server here. Use an invite code to join.");
      }
      if (after) {
        const w = after.welcome;
        after.welcome = w && typeof w === "object" ? { on: !!w.on, msg: censor(str(w.msg, 300)), rules: censor(str(w.rules, 600)), tags: (Array.isArray(w.tags) ? w.tags : []).map(t => str(t, 20).trim()).filter(t => t && !hasBad(t)).slice(0, 8) } : null;
        after.name = str(after.name, 32); after.desc = censor(str(after.desc, 120));
        if (after.bannerBg != null) after.bannerBg = SERVER_BGS.includes(after.bannerBg) ? after.bannerBg : "";
        if (after.bots != null) after.bots = Array.isArray(after.bots) ? [...new Set(after.bots.filter(b => BOT_IDS.includes(b)))] : null;
        if (after.sroles != null) {
          after.sroles = (Array.isArray(after.sroles) ? after.sroles : []).slice(0, 10).map(r => ({ id: str(r && r.id, 12), name: str(r && r.name, 20).trim() || "Role", color: /^#[0-9a-f]{6}$/i.test(r && r.color) ? r.color : "#99aab5" })).filter(r => /^[a-z0-9]{1,12}$/.test(r.id));
          if (after.sroles.some(r => hasBad(r.name))) deny("A role name has a word we don't allow.");
        }
        if (after.smem != null) {
          const ids = new Set((after.sroles || []).map(r => r.id)), o = {};
          Object.entries(after.smem && typeof after.smem === "object" ? after.smem : {}).slice(0, 500).forEach(([u, r]) => { if (/^[A-Za-z0-9_-]{1,80}$/.test(u) && ids.has(r)) o[u] = r; });
          after.smem = o;
        }
        after.chans = (Array.isArray(after.chans) ? after.chans : []).slice(0, 20).map(c => ({ id: str(c.id, 24).toLowerCase().replace(/[^a-z0-9-]/g, "-"), topic: censor(str(c.topic, 120)), ann: !!c.ann, cat: censor(str(c.cat, 24)), see: /^(mods|tag:.{1,20})$/.test(c.see || "") ? c.see : "" })).filter(c => c.id.length >= 2);
        for (const k of ["iconImg", "bannerImg"]) { const m = after[k]; after[k] = m && typeof m === "object" && /^[0-9a-f]{32}$/.test(m.id || "") ? { id: m.id, still: /^[0-9a-f]{32}$/.test(m.still || "") ? m.still : m.id, gif: !!m.gif, anim: !!m.anim } : null; }
        if (!after.chans.length) deny("A server needs at least one channel.");
        if (after.tag != null) { const t = String(after.tag || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 4); if (t && hasBad(t)) deny("That tag has a word we don't allow."); after.tag = t.length >= 2 ? t : ""; }
        if (after.tagIcon != null) after.tagIcon = ["leaf", "banana", "flame", "crown", "star", "heart", "bolt", "paw", "gem", "moon", "drop", "tree"].includes(after.tagIcon) ? after.tagIcon : "leaf";
        if (after.tagColor != null) after.tagColor = /^#[0-9a-f]{6}$/i.test(after.tagColor) ? after.tagColor : "";
        if (after.cat != null) after.cat = SERVER_CATS.includes(after.cat) ? after.cat : "other";
        if (after.stage != null) after.stage = !!after.stage;
        if (after.stageSpk != null) after.stageSpk = (Array.isArray(after.stageSpk) ? after.stageSpk : []).filter(u => typeof u === "string" && /^[A-Za-z0-9_-]{1,80}$/.test(u)).slice(0, 30);
      }
      if (before && after && (before.owner === uid || owner)) {
        const sc = "s-" + seg[1];
        const bb = new Set(before.bans || []), ab = new Set(after.bans || []);
        for (const u of ab) if (!bb.has(u)) await modLogAdd(ctx, extra, sc, { act: "ban", who: u });
        for (const u of bb) if (!ab.has(u)) await modLogAdd(ctx, extra, sc, { act: "unban", who: u });
        const bm = new Set(before.members || []), am = new Set(after.members || []);
        for (const u of bm) if (!am.has(u) && u !== uid && !ab.has(u)) await modLogAdd(ctx, extra, sc, { act: "kick", who: u });
      }
      break;
    }
    case "ch": case "dm": case "gdm": case "th": {
      if (seg.length !== 4 || seg[2] !== "m") deny();
      const key = seg[1];
      // who can see this conversation at all?
      if (top === "ch" && !(await canReadChannel(ctx, key))) deny("You can't post here.");
      if (top === "dm" && !inPair(ctx, key)) deny();
      if (top === "gdm" && !(await inGroup(ctx, key))) deny();
      if (top === "th" && !(await canSeeThread(ctx, key))) deny();
      const ci = top === "ch" ? await chanInfo(ctx, key) : null;
      const isMod = await ctx.can("manageMessages") || (ci && ci.server && ci.server.owner === uid);

      if (!before) { // new message
        if (!after || after.uid !== uid) deny("You can only post as yourself.");
        if (await ctx.timedOut()) deny("You're timed out right now.");
        if (ci && ci.rules) deny("#rules is read-only.");
        if (ci && ci.ann && !(await ctx.can("announce")) && !(ci.server && ci.server.owner === uid)) deny("Only the owner and mods can post announcements.");
        if (top === "dm") {
          const other = key.split("~").find(x => x !== uid) || uid;
          const [prof, blocks] = await getDocs(["profiles/" + other, "data/users/" + other + "/blocks"]);
          if (prof && prof.dmOff) deny("They aren't accepting DMs right now.");
          if (blocks && (blocks.ids || []).includes(uid)) deny("You can't message this gorilla.");
        }
        if (top === "ch") {
          const m = await ctx.meta(), sl = +m.slow[key.replace(/\./g, "~")] || 0;
          if (sl > 0 && !(await ctx.can("slowmode"))) {
            const ok = await cmd("SET", "slow:" + uid + ":" + key, "1", "EX", sl, "NX");
            if (!ok) deny(`Slow mode is on. Wait a bit before posting again.`);
          }
        }
        after = cleanMessage(after);
        after.ts = Date.now();
        if (top !== "th") after.reacts = {};
        if (after.poll) after.votes = {};
        delete after.threadCount; delete after.threadLast; delete after.pinned; delete after.edited; delete after.flags; delete after.cleared;
        if (top === "ch" && ci && after.text) for (const x of await botExtras(ctx, key, ci, after, uid)) extra.push(x);
        // keep the unread index and DM lists up to date
        const ck = convoKeyOfMsgPath(seg);
        if (ck) {
          const priv = top !== "ch";
          const last = { ts: after.ts, uid, text: priv ? "" : str(after.text, 140) };
          if (!priv) { if (after.sticker) last.sticker = 1; if (after.img) last.img = 1; if (after.voice) last.voice = 1; if (after.poll) last.poll = str(after.poll.q, 80); }
          extra.push({ path: "last/" + ck, data: last });
          if (top === "dm" || top === "gdm") await queueMsgPush(ctx, top, key, after, uid);
          if (top === "dm") {
            const other = key.split("~").find(x => x !== uid) || uid;
            const [a, b] = await getDocs(["dmidx/" + uid, "dmidx/" + other]);
            extra.push({ path: "dmidx/" + uid, data: deepMerge(a || {}, { peers: { [other]: after.ts } }) });
            if (other !== uid) extra.push({ path: "dmidx/" + other, data: deepMerge(b || {}, { peers: { [uid]: after.ts } }) });
          }
        }
      } else if (op === "delete") {
        if (before.uid !== uid && !(top === "ch" || top === "th" ? isMod : false)) deny("You can only delete your own messages.");
        if (before.uid !== uid && !String(before.uid || "").startsWith("bot:")) {
          const ck2 = top === "th" ? key.split("~")[0] : key;
          const scope = ck2.startsWith("s-") ? ck2.split(".")[0] : "global";
          await modLogAdd(ctx, extra, scope, { act: "delete", who: before.uid, text: str(before.text, 120) || (before.img ? "[picture]" : before.sticker ? "[sticker]" : "[message]"), where: ck2 });
        }
      } else { // edit / react / vote / pin
        const ck = changedKeys(before, after);
        if (before.uid === uid) {
          if (after.uid !== uid || after.ts !== before.ts) deny();
          if (!isMod) { after.flags = before.flags; after.cleared = before.cleared; if (after.flags === undefined) delete after.flags; if (after.cleared === undefined) delete after.cleared; }
        } else if (ck.every(k => SHARED.includes(k))) {
          if (!onlyMineChanged(ctx, before, after)) deny("You can only change your own reaction or vote.");
        } else if (isMod && ck.every(k => ["poll", "pinned", "cleared", ...SHARED].includes(k)) && onlyMineChanged(ctx, before, after)) {
          // mods may end polls, pin, and mark reported messages as fine
        } else if ((top === "dm" || top === "gdm") && ck.every(k => ["poll", "pinned", ...SHARED].includes(k)) && onlyMineChanged(ctx, before, after)) {
          // mods may end polls and pin
        } else deny("You can only edit your own messages.");
        if ((ck.includes("votes") || ck.includes("reacts")) && await ctx.timedOut()) deny("You're timed out right now.");
        if (ck.includes("poll") && before.poll) after.poll = { q: before.poll.q, opts: before.poll.opts, closed: !!(after.poll && after.poll.closed) };
        after = cleanMessage(after);
      }
      break;
    }
    case "gdmmeta": {
      if (!before) {
        if (!after || after.owner !== uid || !(after.members || []).includes(uid)) deny();
      } else if (!(before.members || []).includes(uid)) deny();
      if (after) {
        after.members = [...new Set((after.members || []).map(String))].slice(0, 6);
        if (after.members.length > 6 || after.members.length < 1) deny("Groups can have up to 6 people.");
        after.name = censor(str(after.name, 32));
      }
      break;
    }
    case "last": return { skip: true }; // the server keeps these itself
    case "gotw": { // Gorilla of the Week: gotw/global (site owner) or gotw/s-<server> (server owner)
      if (seg.length !== 2) deny();
      const key = seg[1]; let srv = null, place = "Gorilla Yapps", chKey = "forest.general";
      if (key.startsWith("s-")) {
        srv = await ctx.server(key.slice(2)); if (!srv) deny();
        if (!(owner || srv.owner === uid)) deny("Only the server owner can pick the Gorilla of the Week.");
        place = String(srv.name || "this server");
        const ch = (srv.chans || []).find(c => c.id === "general" && !c.see) || (srv.chans || []).find(c => !c.ann && !c.see);
        chKey = ch ? key + "." + ch.id : null;
      } else if (key !== "global" || !owner) deny("Only the owner can pick the Gorilla of the Week.");
      if (op === "delete") break;
      const now = Date.now();
      const hist = (Array.isArray(before && before.history) ? before.history : []).concat(before && before.uid ? [{ uid: before.uid, reason: before.reason || "", ts: before.ts || now }] : []).slice(-10);
      if (incoming && incoming.end) { after = { uid: "", reason: "", ts: now, until: 0, by: uid, history: hist }; break; }
      const who = str(incoming && incoming.uid, 80);
      const p = who && /^[A-Za-z0-9_-]{1,80}$/.test(who) ? await ctx.doc("profiles/" + who) : null;
      if (!p) deny("Pick someone who has an account.");
      if (hasBad(incoming.reason)) deny("That has a word we don't allow.");
      const reason = censor(str(incoming.reason, 80)).trim();
      const same = before && before.uid === who && before.until > now;
      after = { uid: who, reason, ts: same ? before.ts : now, until: same ? before.until : now + 7 * 86400000, by: uid, history: same ? (before.history || []) : hist };
      if (!same) {
        if (chKey) extra.push(botMsg(chKey, "yapbot", botGotw(p.display || p.name || "someone", place, reason, true), now));
        await bankAdd(ctx, extra, who, 100, "gotw");
      }
      break;
    }
    case "codes": { // Gorilla Tag room code board: codes/<id>
      if (seg.length !== 2) deny();
      const where = String((before || after || {}).where || "");
      let srv = null;
      if (where.startsWith("s-")) { srv = await ctx.server(where.slice(2)); if (!srv || !(await serverVisible(ctx, srv))) deny("You can't post codes there."); }
      else if (where !== "global") deny();
      const mod = owner || (await ctx.can("manageMessages")) || !!(srv && srv.owner === uid);
      const MODES = ["infection", "casual", "hunt", "paintbrawl", "guardian", "minigames", "other"];
      const MAPS = ["forest", "canyon", "caves", "mountains", "city", "clouds", "beach", "basement", "metropolis", "rotating", "other"];
      const going = g => { const o = {}; Object.entries(g && typeof g === "object" ? g : {}).slice(0, 50).forEach(([k, v]) => { if (v === true && /^[A-Za-z0-9_-]{1,80}$/.test(k)) o[k] = true; }); return o; };
      const spots = v => Math.max(0, Math.min(9, Math.round(+v || 0)));
      if (!before) {
        if (op === "delete") break;
        if (!after || after.by !== uid) deny("Post codes as yourself.");
        if (await ctx.timedOut()) deny("You're timed out right now.");
        const code = String(after.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
        if (code.length < 2 || code.length > 12) deny("Room codes are 2 to 12 letters or numbers.");
        if (hasBad(code) || hasBad(after.note)) deny("That has a word we don't allow.");
        if (!(await cmd("SET", "codepost:" + uid, "1", "EX", 15, "NX"))) deny("Wait a few seconds before posting another code.");
        for (const d of await listDocs("codes")) if (d.data && d.data.by === uid && d.id !== seg[1]) extra.push({ path: "codes/" + d.id, data: null });
        const now = Date.now();
        after = { by: uid, where, code, mode: MODES.includes(after.mode) ? after.mode : "other", map: MAPS.includes(after.map) ? after.map : "other", spots: spots(after.spots), note: censor(str(after.note, 60)), ts: now, until: now + 30 * 60000, going: {} };
      } else if (op === "delete") {
        if (before.by !== uid && !mod) deny("You can only remove your own code.");
      } else if (before.by === uid) {
        if (hasBad(after.note)) deny("That has a word we don't allow.");
        after = Object.assign({}, before, { spots: spots(after.spots), note: censor(str(after.note, 60)), until: Math.min(Date.now() + 30 * 60000, Math.max(before.until || 0, +after.until || 0)), going: going(after.going) });
      } else {
        const gb = going(before.going), ga = going(after && after.going);
        for (const k of new Set([...Object.keys(gb), ...Object.keys(ga)])) if (k !== uid && !!gb[k] !== !!ga[k]) deny("You can only change your own 'I'm joining'.");
        const g = Object.assign({}, gb); if (ga[uid]) g[uid] = true; else delete g[uid];
        after = Object.assign({}, before, { going: g });
      }
      break;
    }
    case "events": {
      if (seg.length !== 2) deny();
      const mid = String((after || before || {}).mapId || "");
      let manager = owner || await ctx.can("manageMessages");
      if (mid.startsWith("s-")) { const srv = await ctx.server(mid.slice(2)); if (!srv || !(await serverVisible(ctx, srv))) deny(); if (srv.owner === uid) manager = true; }
      else if (!BUILTIN_MAPS.includes(mid)) deny();
      if (!before) {
        if (!manager) deny("Only the server owner and mods can make events.");
        if (!after || after.by !== uid) deny();
      } else if (op === "delete") {
        if (!manager && before.by !== uid) deny();
        break;
      } else if (!manager && before.by !== uid) {
        const ck = changedKeys(before, after);
        if (ck.some(k => k !== "going")) deny("You can only say if you're going.");
        const gb = before.going || {}, ga = after.going || {};
        for (const k of new Set([...Object.keys(gb), ...Object.keys(ga)])) if (k !== uid && JSON.stringify(gb[k]) !== JSON.stringify(ga[k])) deny();
      }
      if (after) {
        const going = {}; Object.entries(after.going || {}).slice(0, 500).forEach(([k, v]) => { if (v === true && /^[A-Za-z0-9_-]{1,80}$/.test(k)) going[k] = true; });
        if (!str(after.title, 60).trim() || hasBad(after.title) || hasBad(after.desc)) deny("Pick an event name without bad words.");
        after = { mapId: mid, title: str(after.title, 60).trim(), desc: str(after.desc, 300), when: +after.when || Date.now(), vc: str(after.vc, 30), by: before ? before.by : uid, going, ts: before ? before.ts : Date.now() };
      }
      break;
    }
    case "sounds": {
      const mid = seg[1];
      if (mid.startsWith("s-")) { const sv = await ctx.server(mid.slice(2)); if (!sv || (sv.owner !== uid && !owner)) deny("Only the server owner can change its sounds."); }
      else if (!owner) deny("Only the owner can change map sounds.");
      if (after) {
        const list = Array.isArray(after.list) ? after.list : [];
        if (list.length > 8) deny("Up to 8 sounds per server.");
        after = { list: list.map(x => ({ name: str(x.name, 20).trim(), emoji: str(x.emoji, 8), data: str(x.data, 72000) })).filter(x => /^[a-z0-9_ ]{1,20}$/i.test(x.name) && !hasBad(x.name) && /^data:audio\/(mpeg|ogg|wav|webm|mp4|x-m4a|mp3)(;[a-z0-9=;-]+)?;base64,[A-Za-z0-9+/=]+$/i.test(x.data)) };
      }
      break;
    }
    case "inbox": { // mentions inbox: inbox/<uid> = {items: [...]}
      if (seg.length !== 2) deny();
      const clean = x => ({ id: str(x.id, 40), kind: x.kind === "reply" ? "reply" : "mention", k: str(x.k, 200), from: str(x.from, 80), text: censor(str(x.text, 200)), ts: +x.ts || Date.now() });
      if (seg[1] === uid) { if (after) after = { items: (Array.isArray(after.items) ? after.items : []).slice(0, 50).map(clean) }; break; }
      if (op === "delete") deny();
      const blocks = await ctx.doc("data/users/" + seg[1] + "/blocks");
      if (blocks && (blocks.ids || []).includes(uid)) return { skip: true };
      const prev = before && Array.isArray(before.items) ? before.items : [];
      const have = new Set(prev.map(x => x.id));
      const fresh = (incoming && Array.isArray(incoming.items) ? incoming.items : []).filter(x => x && x.from === uid && !have.has(x.id)).slice(0, 3)
        .map(x => Object.assign(clean(x), { from: uid, ts: Date.now() }));
      if (!fresh.length) return { skip: true };
      await queuePingPush(ctx, seg[1], fresh[0], uid);
      return { after: { items: fresh.concat(prev).slice(0, 50) }, extra };
    }
    case "sreports": { // reports about a server, for that server's owner: sreports/<serverDocId>
      if (seg.length !== 2) deny();
      const srv = await ctx.server(seg[1]); if (!srv) deny();
      const boss = owner || srv.owner === uid;
      const clean = x => ({ id: str(x.id, 40), by: str(x.by, 80), k: str(x.k, 200), mid: str(x.mid, 80), author: str(x.author, 80), text: censor(str(x.text, 300)), reason: str(x.reason, 40), details: censor(str(x.details, 300)), ts: +x.ts || Date.now(), status: x.status === "done" ? "done" : "open", outcome: str(x.outcome, 80), srv: seg[1] });
      if (boss) {
        if (op === "delete") break;
        const items = ((after && after.items) || []).slice(-50).map(clean);
        for (const it of items) {
          const old = ((before && before.items) || []).find(x => x.id === it.id);
          if (it.status === "done" && old && old.status !== "done" && it.by) { // let the person who reported know
            const rd = await ctx.doc("reports/" + it.by);
            if (rd && Array.isArray(rd.items) && rd.items.some(x => x.id === it.id)) extra.push({ path: "reports/" + it.by, data: { items: rd.items.map(x => x.id === it.id ? Object.assign({}, x, { status: "done", outcome: it.outcome || "handled", doneTs: Date.now() }) : x) } });
          }
        }
        after = { items };
        break;
      }
      if (op === "delete") deny();
      if (!(await serverVisible(ctx, srv))) deny();
      const prev = (before && before.items) || [], have = new Set(prev.map(x => x.id));
      const fresh = ((incoming && incoming.items) || []).filter(x => x && x.by === uid && !have.has(x.id)).slice(0, 1).map(x => Object.assign(clean(x), { by: uid, ts: Date.now(), status: "open", outcome: "" }));
      if (!fresh.length) return { skip: true };
      return { after: { items: prev.concat(fresh).slice(-50) }, extra };
    }
    case "bank": { // banana changes from bots; only the owner can mark items as collected
      if (seg.length !== 2 || seg[1] !== uid || op === "delete") deny();
      const done = new Set(Array.isArray(incoming && incoming.done) ? incoming.done.map(String) : []);
      return { after: { items: ((before && before.items) || []).filter(x => !done.has(String(x.id))) }, extra };
    }
    case "gifts": { // gift boxes: gifts/<to> = {items: [{id, from, item, note, ts}]}
      if (seg.length !== 2) deny();
      const giftId = v => typeof v === "string" && /^[a-z0-9-]{1,24}$/.test(v);
      const clean = x => ({ id: str(x.id, 40), from: str(x.from, 80), item: giftId(x.item) ? x.item : "", note: censor(str(x.note, 60)), ts: +x.ts || Date.now() });
      if (seg[1] === uid) { if (after) after = { items: (Array.isArray(after.items) ? after.items : []).slice(-30).map(clean).filter(x => x.item) }; break; }
      if (op === "delete") deny();
      const blocks = await ctx.doc("data/users/" + seg[1] + "/blocks");
      if (blocks && (blocks.ids || []).includes(uid)) return { skip: true };
      const fr = await ctx.doc("data/users/" + seg[1] + "/friends");
      if (!fr || !(fr.ids || []).includes(uid)) deny("You can only send gifts to friends.");
      const prev = before && Array.isArray(before.items) ? before.items : [];
      const have = new Set(prev.map(x => x.id));
      const fresh = (incoming && Array.isArray(incoming.items) ? incoming.items : []).filter(x => x && x.from === uid && !have.has(x.id) && giftId(x.item)).slice(0, 1)
        .map(x => Object.assign(clean(x), { from: uid, ts: Date.now() }));
      if (!fresh.length) return { skip: true };
      if (prev.length >= 30) deny("Their gift box is full right now.");
      return { after: { items: prev.concat(fresh) }, extra };
    }
    case "freq": { // friend request boxes: freq/<to> = {items: {<from>: time | "ok" | "rm"}}
      if (seg.length !== 2 || op === "delete" && seg[1] !== uid) deny();
      const okVal = v => typeof v === "number" || v === "ok" || v === "rm";
      const clean = items => { const o = {}; Object.entries(items && typeof items === "object" ? items : {}).slice(0, 300).forEach(([k, v]) => { if (/^[A-Za-z0-9_-]{1,80}$/.test(k) && okVal(v)) o[k] = v; }); return o; };
      if (seg[1] === uid) { if (after) after = { items: clean(after.items) }; break; }
      // someone else's box: only my own entry changes, merged in on the server (I can't read their box)
      const blocks = await ctx.doc("data/users/" + seg[1] + "/blocks");
      if (blocks && (blocks.ids || []).includes(uid)) return { skip: true };
      const mine = incoming && incoming.items ? incoming.items[uid] : undefined;
      if (mine != null && !okVal(mine)) deny();
      const items = clean(before && before.items);
      if (mine == null) delete items[uid]; else items[uid] = typeof mine === "number" ? Date.now() : mine;
      return { after: { items }, extra };
    }
    case "dmidx": {
      if (seg[1] !== uid) return { skip: true };
      if (after) { const peers = {}; for (const [k, v] of Object.entries(after.peers || {})) if (typeof v === "number") peers[str(k, 80)] = v; after = { peers }; }
      break;
    }
    case "reports":
      if (seg[1] !== uid && !owner) deny();
      if (after) after = { items: (Array.isArray(after.items) ? after.items : []).slice(-25) };
      break;
    case "data":
      if (seg[0] !== "data" || seg[1] !== "users" || seg[2] !== uid || seg.length !== 4) deny();
      if (seg[3] === "login") deny(); // passwords live elsewhere on this site
      if (seg[3] === "push" && after) after = { subs: cleanPushSubs(after.subs) };
      break;
    case "images": deny("Upload images with the picture button.");
    default: deny();
  }
  return { after, extra };
}

const H = {};
/* ===== api/auth ===== */
{
// Accounts: sign up, log in (with two-step codes), change password, reset codes from the owner, delete account.

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const pwProblem = pw => typeof pw !== "string" || pw.length < 8 || pw.length > 200 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw)
  ? "Pick a password with at least 8 characters, including a letter and a number." : null;
const getLogin = async uid => { const v = await cmd("GET", "login:" + uid); return v ? JSON.parse(v) : null; };
const putLogin = (uid, l) => cmd("SET", "login:" + uid, JSON.stringify(l));

async function limit(key, max, seconds, msg) {
  const [n] = await pipe([["INCR", "rl:" + key], ["EXPIRE", "rl:" + key, seconds, "NX"]]);
  if (n > max) throw new Fail(429, "slow_down", msg || "Too many tries. Wait a few minutes and try again.");
}
const ip = req => String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "?").split(",")[0].trim();
const session = async uid => {
  const [o] = await getDocs(["meta/owner"]);
  const l = await getLogin(uid);
  return { uid, email: l && l.email, token: signToken(uid, l && l.pv), owner: !!(o && o.uid === uid) };
};

H.auth = api(async (body, auth, req) => {
  const { action } = body;

  if (action === "signup") {
    const email = String(body.email || "").trim().toLowerCase();
    if (!EMAIL_RE.test(email)) throw new Fail(400, "email", "That doesn't look like an email address.");
    const bad = pwProblem(body.password); if (bad) throw new Fail(400, "weak", bad);
    await limit("signup:" + ip(req), 10, 3600, "Too many new accounts from here. Try again later.");
    const uid = "u" + randomId(19);
    const ok = await cmd("SET", "email:" + email, uid, "NX");
    if (!ok) throw new Fail(409, "taken", "That email already has an account. Try logging in.");
    const { salt, hash } = hashPassword(body.password);
    await putLogin(uid, { email, salt, hash, pv: 1, created: Date.now() });
    // The very first account owns the site.
    const first = await cmd("SET", "d:meta/owner", JSON.stringify({ uid, claimed: Date.now() }), "NX");
    if (first) await writeDocs([{ path: "meta/owner", data: { uid, claimed: Date.now() } }]);
    return session(uid);
  }

  if (action === "login") {
    const email = String(body.email || "").trim().toLowerCase();
    await limit("login:" + email, 12, 900);
    await limit("loginip:" + ip(req), 40, 900);
    const uid = await cmd("GET", "email:" + email);
    const l = uid && await getLogin(uid);
    if (!l || !checkPassword(String(body.password || ""), l.salt, l.hash)) throw new Fail(401, "wrong", "Email or password is wrong.");
    const sec = await getDoc("data/users/" + uid + "/security");
    if (sec && sec.on && sec.secret) {
      const raw = String(body.code || "").trim();
      if (!raw) return { need2fa: true };
      let ok = totpOk(sec.secret, raw);
      const clean = raw.replace(/[^a-z0-9]/gi, "").toLowerCase();
      if (!ok && clean.length === 10) {
        const h = sha256(clean), list = sec.backup || [];
        if (list.includes(h)) { ok = true; await writeDocs([{ path: "data/users/" + uid + "/security", data: Object.assign({}, sec, { backup: list.filter(x => x !== h) }) }]); }
      }
      if (!ok) throw new Fail(401, "code", "That code didn't work. Check the time on your phone and try again.");
    }
    await cmd("DEL", "rl:login:" + email);
    return session(uid);
  }

  if (action === "reset") { // new password using a one-time code the owner made
    const email = String(body.email || "").trim().toLowerCase();
    await limit("reset:" + ip(req), 10, 900);
    const bad = pwProblem(body.password); if (bad) throw new Fail(400, "weak", bad);
    const code = String(body.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
    const uid = await cmd("GET", "email:" + email);
    const forUid = code && await cmd("GET", "resetcode:" + sha256(code));
    if (!uid || forUid !== uid) throw new Fail(400, "code", "That reset code doesn't match this email. Ask the owner for a new one.");
    const l = await getLogin(uid), { salt, hash } = hashPassword(body.password);
    await putLogin(uid, Object.assign(l, { salt, hash, pv: (l.pv || 1) + 1 }));
    await cmd("DEL", "resetcode:" + sha256(code));
    return session(uid);
  }

  if (action === "invite") { // what a server invite link shows, even before you log in
    await limit("inv:" + ip(req), 60, 60, "Too many invite checks. Wait a minute.");
    const code = String(body.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
    const gone = "This invite link doesn't work anymore. Ask your friend for a new one.";
    if (code.length < 4) throw new Fail(404, "code", gone);
    const list = await listDocs("servers");
    const hit = list.find(d => d.data && d.data.name && String(d.data.code || "").toUpperCase() === code);
    if (!hit) throw new Fail(404, "code", gone);
    const s = hit.data, HEX = /^[0-9a-f]{32}$/;
    const img = v => v && HEX.test(v.id || "") ? { id: v.id, still: HEX.test(v.still || "") ? v.still : v.id, gif: !!v.gif, anim: !!v.anim } : null;
    let members;
    if (s.private) members = new Set([s.owner].concat(s.members || [])).size;
    else members = (await listDocs("profiles")).filter(p => p.id === s.owner || (Array.isArray(p.data && p.data.srvJoined) && p.data.srvJoined.includes(hit.id))).length;
    let from = null;
    const fn = String(body.from || "").toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 16);
    if (fn.length >= 3) {
      const fu = await cmd("GET", "name:" + fn);
      const p = fu ? await getDoc("profiles/" + fu) : null;
      if (p) from = { name: String(p.name || "").slice(0, 16), display: String(p.display || p.name || "").slice(0, 32), fur: p.fur, hat: p.hat, face: p.face, pattern: p.pattern, acc: p.acc, avatar: img(p.avatar) };
    }
    return { docId: hit.id, name: String(s.name).slice(0, 32), desc: String(s.desc || "").slice(0, 120), icon: String(s.icon || "").slice(0, 8), color: /^#[0-9a-f]{6}$/i.test(s.color || "") ? s.color : "#2e7d32",
      bannerBg: String(s.bannerBg || "").slice(0, 20), bannerImg: img(s.bannerImg), iconImg: img(s.iconImg), private: !!s.private, members: Math.max(1, members), from };
  }

  const uid = needUser(auth);
  const l = await getLogin(uid);
  if (!l || (l.pv || 1) !== (auth.pv || 1)) throw new Fail(401, "auth", "Please log in again.");

  if (action === "me") return session(uid);

  if (action === "turn") { // short-lived logins for the free Open Relay TURN server (helps voice through strict networks)
    const user = Math.floor(Date.now() / 1000 + 6 * 3600) + ":" + uid;
    const credential = crypto.createHmac("sha1", "openrelayprojectsecret").update(user).digest("base64");
    const host = "staticauth.openrelay.metered.ca";
    return { iceServers: [
      { urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"] },
      { urls: ["turn:" + host + ":80", "turn:" + host + ":443", "turn:" + host + ":443?transport=tcp", "turns:" + host + ":443?transport=tcp"], username: user, credential }
    ] };
  }

  if (action === "change") {
    if (!checkPassword(String(body.old || ""), l.salt, l.hash)) throw new Fail(401, "wrong", "Your current password is wrong.");
    const bad = pwProblem(body.password); if (bad) throw new Fail(400, "weak", bad);
    const { salt, hash } = hashPassword(body.password);
    await putLogin(uid, Object.assign(l, { salt, hash, pv: (l.pv || 1) + 1 }));
    return session(uid);
  }

  if (action === "resetCode") { // owner makes a one-time code for someone who forgot their password
    const o = await getDoc("meta/owner");
    if (!o || o.uid !== uid) throw new Fail(403, "denied", "Only the owner can make reset codes.");
    const target = await cmd("GET", "name:" + String(body.name || "").toLowerCase());
    if (!target) throw new Fail(404, "nobody", "No gorilla has that username.");
    const code = Array.from({ length: 8 }, () => "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[Math.floor(Math.random() * 32)]).join("");
    await cmd("SET", "resetcode:" + sha256(code), target, "EX", 86400);
    return { code, uid: target };
  }

  if (action === "delete") {
    const prof = await getDoc("profiles/" + uid);
    const paths = ["profiles/" + uid, "dmidx/" + uid, ...["security", "friends", "blocks", "prefs"].map(k => "data/users/" + uid + "/" + k)];
    await writeDocs(paths.map(path => ({ path, data: null })));
    const cmds = [["DEL", "login:" + uid], ["DEL", "email:" + l.email]];
    if (prof && prof.nameLower) cmds.push(["DEL", "name:" + prof.nameLower]);
    await pipe(cmds);
    return { ok: true };
  }

  throw new Fail(400, "action", "Unknown action.");
});

}
/* ===== api/db ===== */
{
// The database: read, list and change documents. Every request is checked by lib/rules.js.

async function pvOk(uid, pv) {
  const v = await cmd("GET", "login:" + uid);
  if (!v) return false;
  try { return (JSON.parse(v).pv || 1) === (pv || 1); } catch (e) { return false; }
}

H.db = api(async (body, auth, req) => {
  const uid = needUser(auth);
  const ops = Array.isArray(body.ops) ? body.ops.slice(0, 40) : [];
  const ctx = makeCtx(uid);
  const results = [];
  const writes = [];
  const redisExtra = [];
  let checkedPv = false;

  for (const o of ops) {
    try {
      if (o.op === "get") {
        checkPath(o.path, "doc");
        const data = await ctx.doc(o.path);
        const r = await readable(ctx, o.path, data);
        if (data && r == null) results.push({ error: "denied" });
        else results.push({ data: r ?? null });
      } else if (o.op === "list") {
        checkPath(o.path, "col");
        if (!(await canListCollection(ctx, o.path))) { results.push({ error: "denied" }); continue; }
        const isMsgs = o.path.endsWith("/m");
        const lim = Math.max(1, Math.min(+o.limit || (isMsgs ? 60 : 500), isMsgs ? 1000 : 500));
        const docs = await listDocs(o.path, { limit: lim, newestFirst: true });
        const out = [];
        for (const d of docs) { ctx.prime(o.path + "/" + d.id, d.data); const r = await readable(ctx, o.path + "/" + d.id, d.data); if (r != null) out.push({ id: d.id, data: r }); }
        results.push({ docs: out });
      } else if (o.op === "set" || o.op === "update" || o.op === "delete") {
        if (!checkedPv) { if (!(await pvOk(uid, auth.pv))) throw new Fail(401, "auth", "Please log in again."); checkedPv = true; }
        checkPath(o.path, "doc");
        if (o.op !== "delete" && (!o.data || typeof o.data !== "object" || Array.isArray(o.data))) throw new Fail(400, "bad_data", "Bad data.");
        if (o.data && JSON.stringify(o.data).length > 600000) throw new Fail(413, "too_big", "That's too big to save.");
        const before = await ctx.doc(o.path);
        if (o.op === "update" && !before && !o.upsert) { /* merge-write creates it, like the old site */ }
        const res = await checkWrite(ctx, o.op, o.path, before, o.data);
        if (res.skip) { results.push({ ok: true, skipped: true }); continue; }
        writes.push({ path: o.path, data: res.after });
        ctx.prime(o.path, res.after);
        for (const x of res.extra) {
          if (x.redis) redisExtra.push(x.redis);
          else { writes.push(x); ctx.prime(x.path, x.data); }
        }
        results.push({ ok: true, data: res.after });
      } else if (o.op === "joinServer") {
        const code = String(o.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
        if (code.length < 4) throw new Fail(400, "code", "No server has that code. Check it and try again.");
        const list = await listDocs("servers");
        const hit = list.find(d => d.data && d.data.name && String(d.data.code || "").toUpperCase() === code);
        if (!hit) throw new Fail(404, "code", "No server has that code. Check it and try again.");
        if ((hit.data.bans || []).includes(uid)) throw new Fail(403, "banned", "You can't join that server.");
        if (!hit.data.private) { results.push({ ok: true, docId: hit.id, name: hit.data.name, public: true }); continue; }
        if (!(hit.data.members || []).includes(uid) && hit.data.owner !== uid) {
          const after = Object.assign({}, hit.data, { members: (hit.data.members || []).concat(uid) });
          writes.push({ path: "servers/" + hit.id, data: after });
          ctx.prime("servers/" + hit.id, after);
          if (serverBots(hit.data).includes("modbot")) {
            const me = (await ctx.doc("profiles/" + uid)) || {};
            const ch = (hit.data.chans || []).find(c => c.id === "general" && !c.see) || (hit.data.chans || []).find(c => !c.ann && !c.see);
            if (ch) writes.push(botMsg("s-" + hit.id + "." + ch.id, "modbot", botWelcome(me.display || me.name || "new monke", hit.data.name || "the server"), Date.now()));
          }
        }
        results.push({ ok: true, docId: hit.id, name: hit.data.name });
      } else if (o.op === "pushKey") {
        results.push({ key: (await vapidKeys()).pub });
      } else if (o.op === "pushTest") {
        if (!(await cmd("SET", "pushtest:" + uid, "1", "EX", 5, "NX"))) throw new Fail(429, "slow_down", "Wait a few seconds before sending another test.");
        (ctx.pushes = ctx.pushes || []).push({ uid, payload: { title: "Gorilla Yapps", body: "Notifications work! You'll get one like this for DMs and pings.", tag: "gy-test", url: "/" } });
        results.push({ ok: true });
      } else if (o.op === "newId") {
        results.push({ id: randomId(20) });
      } else results.push({ error: "bad_op" });
    } catch (e) {
      if (e instanceof Fail) {
        if (e.status === 401) throw e;
        results.push({ error: e.code, message: e.publicMessage });
      } else throw e;
    }
  }
  // Quick per-user write limit so one account can't flood the database.
  if (writes.length) {
    const [n] = await pipe([["INCR", "rl:w:" + uid], ["EXPIRE", "rl:w:" + uid, 60, "NX"]]);
    if (n > 90) throw new Fail(429, "slow_down", "Whoa, slow down! Wait a minute before doing more.");
  }
  if (redisExtra.length) await pipe(redisExtra);
  const seq = await writeDocs(writes);
  if (ctx.pushes && ctx.pushes.length) {
    const host = String((req && req.headers && (req.headers["x-forwarded-host"] || req.headers.host)) || "").replace(/[^A-Za-z0-9.:-]/g, "");
    const subject = !host || /^(localhost|127\.)/.test(host) ? "https://gorilla-yapp.vercel.app" : "https://" + host.replace(/:\d+$/, "");
    try { await sendPushes(ctx.pushes, subject); } catch (e) {}
  }
  return { results, seq };
});

}
/* ===== api/sync ===== */
{
// Keeps every open tab up to date: what changed since last time, who's online, typing and voice-room events.

const STALE = 90000;
const parseEntry = x => { const i = x.indexOf("|"); return { s: +x.slice(0, i), v: x.slice(i + 1) }; };
const CONN_RE = /^[A-Za-z0-9_-]{6,40}$/;

H.sync = api(async (body, auth) => {
  const uid = needUser(auth);
  const now = Date.now();
  const conn = CONN_RE.test(body.conn || "") ? body.conn : null;
  const cursor = Number.isFinite(+body.cursor) && body.cursor !== null ? +body.cursor : null;

  const pairs = [], cmds = [];
  // ---- presence ----
  if (conn && body.leave) { cmds.push(["HDEL", "pres", conn]); pairs.push("log", "~pres"); }
  else if (conn && (body.pres || body.beat)) {
    let prev = null;
    if (!body.pres) { const [p] = await pipe([["HGET", "pres", conn]]); try { prev = p && JSON.parse(p); } catch (e) {} }
    const state = body.pres && typeof body.pres === "object" ? body.pres : (prev && prev.p) || {};
    const json = JSON.stringify({ by: uid, p: state, t: now });
    if (json.length > 2000) throw new Fail(413, "too_big", "Too much presence data.");
    cmds.push(["HSET", "pres", conn, json]);
    if (body.pres || !prev || prev.t < now - STALE) pairs.push("log", "~pres");
  }
  // ---- events (typing, voice) ----
  const emits = Array.isArray(body.emits) ? body.emits.slice(0, 10) : [];
  if (emits.length) {
    const [n] = await pipe([["INCR", "rl:ev:" + uid], ["EXPIRE", "rl:ev:" + uid, 60, "NX"]]);
    if (n > 120) throw new Fail(429, "slow_down", "Too many events. Slow down a little.");
    for (const e of emits) {
      const json = JSON.stringify({ topic: String(e.topic || "").slice(0, 30), data: e.data === undefined ? null : e.data, by: uid, peer: conn, t: now, eid: typeof e.eid === "string" ? e.eid.slice(0, 24) : undefined });
      if (json.length > 4000) continue;
      pairs.push("ev", json);
    }
    if (emits.length) pairs.push("log", "~ev");
  }
  if (pairs.length) cmds.push(appendCmd(pairs));
  cmds.push(["GET", "seq"]);
  const out = await pipe(cmds);
  const seq = +(out[out.length - 1] || 0);

  const res = { seq };
  let wantPeers = !!body.peers || cursor === null;
  if (cursor !== null && seq > cursor) {
    const [log] = await pipe([["LRANGE", "log", 0, 399]]);
    const entries = (log || []).map(parseEntry).filter(e => e.s > cursor);
    const oldest = log && log.length ? parseEntry(log[log.length - 1]).s : 0;
    if (log && log.length >= 400 && oldest > cursor + 1) { res.reset = true; wantPeers = true; }
    else {
      const paths = [...new Set(entries.map(e => e.v))];
      if (paths.includes("~pres")) wantPeers = true;
      if (paths.includes("~ev")) {
        const [ev] = await pipe([["LRANGE", "ev", 0, 99]]);
        res.events = (ev || []).map(parseEntry).filter(e => e.s > cursor).reverse().map(e => { try { return JSON.parse(e.v); } catch (x) { return null; } })
          .filter(e => e && e.t > now - 20000);
      }
      const docPaths = paths.filter(p => !p.startsWith("~")).slice(0, 300);
      if (docPaths.length) {
        const ctx = makeCtx(uid);
        const docs = await getDocs(docPaths);
        const changes = [];
        for (let i = 0; i < docPaths.length; i++) {
          const path = docPaths[i], data = docs[i];
          ctx.prime(path, data);
        }
        for (let i = 0; i < docPaths.length; i++) {
          const path = docPaths[i], data = docs[i];
          if (data == null) {
            // a deleted document: tell people who could have seen that kind of thing
            if (await readable(ctx, path, { members: [uid], uid, owner: uid }) != null) changes.push({ path, data: null });
          } else {
            const r = await readable(ctx, path, data);
            if (r != null) changes.push({ path, data: r });
          }
        }
        res.changes = changes;
      }
    }
  }
  if (wantPeers) {
    const [all] = await pipe([["HGETALL", "pres"]]);
    const peers = [], stale = [];
    const arr = Array.isArray(all) ? all : Object.entries(all || {}).flat();
    for (let i = 0; i < arr.length; i += 2) {
      let x = null; try { x = JSON.parse(arr[i + 1]); } catch (e) {}
      if (!x || x.t < now - STALE) { stale.push(arr[i]); continue; }
      const p = Object.assign({}, x.p || {});
      if (x.by !== uid && typeof p.k === "string" && /^(dm|gdm)~/.test(p.k)) p.k = "private";
      peers.push({ peer: arr[i], by: x.by, presence: p, t: x.t });
    }
    if (stale.length) await pipe([["HDEL", "pres", ...stale]]);
    res.peers = peers;
  }
  return res;
});

}
/* ===== api/upload ===== */
{
// Pictures: shrunk in the browser first, then saved here for 60 days.

const RE = /^data:image\/(jpeg|png|webp|gif);base64,([A-Za-z0-9+/=]+)$/;
H.upload = api(async (body, auth) => {
  const uid = needUser(auth);
  const m = RE.exec(String(body.data || ""));
  if (!m) throw new Fail(400, "unsupported_type", "Only pictures can be uploaded.");
  if (body.data.length > 700000) throw new Fail(413, "too_large", "That picture is too big.");
  const [n] = await pipe([["INCR", "rl:img:" + uid], ["EXPIRE", "rl:img:" + uid, 86400, "NX"]]);
  if (n > 40) throw new Fail(429, "slow_down", "You've shared a lot of pictures today. Try again tomorrow.");
  const id = crypto.randomBytes(16).toString("hex");
  await pipe([["SET", "img:" + id, body.data, "EX", 60 * 86400]]);
  return { id, url: "/api/img?id=" + id, sizeBytes: body.data.length, contentType: "image/" + m[1] };
});

}
/* ===== api/img ===== */
{
// Sends a saved picture. Pictures are cached by Vercel, so this rarely runs twice for the same one.

H.img = async function handler(req, res) {
  const id = String((req.query && req.query.id) || new URL(req.url, "http://x").searchParams.get("id") || "");
  if (!/^[0-9a-f]{32}$/.test(id) || !configured()) { res.status(404).end("Not found"); return; }
  const v = await cmd("GET", "img:" + id).catch(() => null);
  const m = v && /^data:(image\/[a-z]+);base64,(.+)$/.exec(v);
  if (!m) { res.setHeader("Cache-Control", "public, max-age=60"); res.status(404).end("Not found"); return; }
  res.setHeader("Content-Type", m[1]);
  res.setHeader("Cache-Control", "public, max-age=31536000, s-maxage=31536000, immutable");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.status(200).end(Buffer.from(m[2], "base64"));
}

}
export default async function route(req, res) {
  const fn = String((req.query && req.query.fn) || new URL(req.url, "http://x").pathname.split("/").pop());
  const h = Object.prototype.hasOwnProperty.call(H, fn) ? H[fn] : null;
  if (!h) { res.status(404).json({ error: "not_found", message: "Not found." }); return; }
  return h(req, res);
}