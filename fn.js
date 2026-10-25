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

/* ===== lib/bots.js ===== */
// Built-in helper bots (no AI: every answer comes from the lists and rules below).
// This file runs on the server (website) AND is copied into the page for the Claude app version.
const BOT_LIST = {
  yapbot: { name: "YapBot", fur: "#5865f2", hat: "astronaut", face: "robot", tag: "Helper",
    desc: "Rolls dice, flips coins, answers the magic 8-ball, picks for you and shows server and user info.",
    cmds: [["!help", "See every bot command"], ["!ping", "Check that the bots are awake"], ["!roll", "Roll dice, like !roll 2d6"], ["!flip", "Flip a coin"], ["!8ball", "Ask a yes-or-no question"], ["!choose", "Pick one, like !choose pizza | tacos"], ["!server", "Info about this server"], ["!whois", "Info about someone, like !whois @name"]] },
  funbot: { name: "FunBot", fur: "#ff6fb5", hat: "propeller", face: "silly", tag: "Games",
    desc: "Jokes, animal facts, trivia with banana prizes, hugs and compliments.",
    cmds: [["!joke", "Tell a joke"], ["!fact", "A real animal fact"], ["!monke", "Wise words from a monke"], ["!trivia", "Start a trivia question (winner gets 5 🍌)"], ["!answer", "Answer the trivia, like !answer mars"], ["!rate", "Rate anything out of 10"], ["!hug", "Hug someone, like !hug @name"], ["!compliment", "Say something nice to someone"]] },
  bananabot: { name: "BananaBot", fur: "#f0b232", hat: "chef", face: "happy", tag: "Economy",
    desc: "Check bananas and levels, see the top 5, and give bananas to friends.",
    cmds: [["!bananas", "How many bananas you (or @name) have"], ["!level", "Your level and XP"], ["!top", "Top 5 banana holders"], ["!give", "Give bananas, like !give @name 10"]] },
  modbot: { name: "ModBot", fur: "#3f8fe6", hat: "viking", face: "cool", tag: "Safety",
    desc: "Welcomes new members, warns people who spam, and lets mods give warnings.",
    cmds: [["!rules", "Show the rules"], ["!report", "How to report someone"], ["!warn", "Mods only: !warn @name reason"]] }
};
const BOT_IDS = Object.keys(BOT_LIST);
const DEFAULT_BOTS = BOT_IDS.slice();
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
async function botRun(text, env) {
  const m = /^!([a-z0-9]+)\b\s*([\s\S]*)$/i.exec(String(text || "").trim());
  if (!m) return [];
  const cmd = m[1].toLowerCase(), arg = m[2].trim().slice(0, 200), r = env.rand || Math.random;
  const bot = cmd === "help" ? "yapbot" : BOT_CMD[cmd];
  if (!bot || !env.bots.includes(bot)) return [];
  const me = env.author, nm = p => "**" + (p.display || p.name || "someone") + "**";
  const say = t => [{ bot, text: t }];
  const who = async () => { const mm = /@([A-Za-z0-9_]{2,16})/.exec(arg); return mm ? await env.findUser(mm[1]) : null; };
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
    case "bananas": { const p = (await who()) || me; return say("🍌 " + nm(p) + " has **" + (p.bananas || 0) + "** bananas."); }
    case "level": { const p = (await who()) || me, xp = p.xp ?? p.bananas ?? 0, lv = botLevel(xp); return say("⬆️ " + nm(p) + " is level **" + lv + "** (" + xp + " XP, " + (3 * lv * lv - xp) + " to go)"); }
    case "top": {
      const t = await env.top(5);
      return say(t.length ? "🏆 **Top bananas**\n" + t.map((p, i) => ["🥇", "🥈", "🥉", "4.", "5."][i] + " " + nm(p) + ": " + (p.bananas || 0) + " 🍌").join("\n") : "🏆 Nobody has bananas yet!");
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
function botWelcome(name, place) { return "👋 Welcome to **" + place + "**, **" + name + "**! Type `!help` to see what the bots can do."; }
function botBirthday(name) { return "🎂 Happy birthday, **" + name + "**! 🎉 The whole troop hopes you have an awesome day! (+50 🍌 from the bots)"; }
function botGotw(name, place, reason, prize) { return "🏆 **" + name + "** is the Gorilla of the Week in **" + place + "**!" + (reason ? " “" + reason + "”" : "") + " Everyone say GG!" + (prize ? " (+100 🍌)" : ""); }
function botSpamWarn(name) { return "🛑 Whoa, **" + name + "**, slow down! Please don't spam."; }

{ BOT_LIST, BOT_IDS, DEFAULT_BOTS, botRun, botWelcome, botSpamWarn, botBirthday, botGotw };

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
    case "meta": case "mapcfg": case "mod": case "profiles": case "emoji": case "images": return data;
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
    case "data": return seg[2] === ctx.uid ? data : null;
    default: return null;
  }
}
// Can the user list this collection at all? (Individual docs are still filtered by readable.)
async function canListCollection(ctx, colPath) {
  const seg = colPath.split("/");
  if (seg.length === 1) return ["meta", "mapcfg", "mod", "profiles", "emoji", "servers", "gdmmeta", "last", "reports", "dmidx", "events", "sounds", "codes", "gotw"].includes(seg[0]);
  if (seg.length === 3 && seg[2] === "m") {
    if (seg[0] === "ch") return canReadChannel(ctx, seg[1]);
    if (seg[0] === "dm") return inPair(ctx, seg[1]);
    if (seg[0] === "gdm") return inGroup(ctx, seg[1]);
    if (seg[0] === "th") return canSeeThread(ctx, seg[1]);
  }
  return false;
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
function botMsg(key, bot, text, ts) { return { path: "ch/" + key + "/m/" + randomId(20), data: { uid: "bot:" + bot, ts, text: String(text).slice(0, 1500), reacts: {}, bot: 1 } }; }
async function botExtras(ctx, key, ci, msg, uid) {
  const bots = ci.server ? serverBots(ci.server) : DEFAULT_BOTS.slice();
  const extra = []; if (!bots.length) return extra;
  const text = String(msg.text || "");
  const getP = async u => { const p = await ctx.doc("profiles/" + u); return p ? Object.assign({ uid: u }, p) : null; };
  const me = (await getP(uid)) || { uid, name: "someone" };
  // ModBot: warn people who post the same thing over and over
  if (bots.includes("modbot") && !text.startsWith("!")) {
    const sk = "spam:" + uid + ":" + key, prev = await cmd("GET", sk);
    let st = { t: "", n: 0 }; try { if (prev) st = JSON.parse(prev); } catch (e) {}
    const norm = text.toLowerCase().trim();
    st = norm && norm === st.t ? { t: norm, n: st.n + 1 } : { t: norm, n: 1 };
    await cmd("SET", sk, JSON.stringify(st), "EX", 40);
    if (st.n >= 3 && await cmd("SET", "spamwarn:" + uid + ":" + key, "1", "EX", 60, "NX")) extra.push(botMsg(key, "modbot", botSpamWarn(me.display || me.name), msg.ts + 1));
    return extra;
  }
  if (!text.startsWith("!")) return extra;
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
    rand: Math.random
  };
  if (!(await cmd("SET", "botrl:" + uid, "1", "PX", 1000, "NX"))) return extra; // one command a second per person
  const out = await botRun(text, env);
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
  if (o.flags != null) { const f = {}; Object.entries(o.flags && typeof o.flags === "object" ? o.flags : {}).slice(0, 50).forEach(([k, v]) => { if (v === true && /^[A-Za-z0-9_-]{1,80}$/.test(k)) f[k] = true; }); o.flags = f; }
  if (o.cleared != null) o.cleared = !!o.cleared;
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
      break;
    case "mapcfg":
      if (!owner) deny("Only the owner can change map settings.");
      break;
    case "mod": {
      if (seg[1] === "slow" && !(await ctx.can("slowmode"))) deny("You need the slow mode power.");
      if (seg[1] === "timeouts") {
        if (!(await ctx.can("timeout"))) deny("You need the timeout power.");
        const m = await ctx.meta();
        if (after && m.owner && after[m.owner]) deny("The owner can't be timed out.");
      }
      if (!["slow", "timeouts"].includes(seg[1])) deny();
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
        else { if (hasBad(a.text)) deny("Your activity has a word we don't allow."); after.activity = { type: a.type, text: str(a.text, 40).trim(), until: +a.until || 0 }; }
      }
      if (after) {
        const idOk = v => typeof v === "string" && /^[a-z0-9-]{0,24}$/.test(v);
        for (const k of ["acc", "effect", "hat", "face", "pattern", "nameColor", "deco"]) if (after[k] != null && !idOk(after[k])) after[k] = "";
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
          if (top === "dm") {
            const other = key.split("~").find(x => x !== uid) || uid;
            const [a, b] = await getDocs(["dmidx/" + uid, "dmidx/" + other]);
            extra.push({ path: "dmidx/" + uid, data: deepMerge(a || {}, { peers: { [other]: after.ts } }) });
            if (other !== uid) extra.push({ path: "dmidx/" + other, data: deepMerge(b || {}, { peers: { [uid]: after.ts } }) });
          }
        }
      } else if (op === "delete") {
        if (before.uid !== uid && !(top === "ch" || top === "th" ? isMod : false)) deny("You can only delete your own messages.");
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
        const hit = list.find(d => d.data.private && String(d.data.code || "").toUpperCase() === code);
        if (!hit) throw new Fail(404, "code", "No server has that code. Check it and try again.");
        if ((hit.data.bans || []).includes(uid)) throw new Fail(403, "banned", "You can't join that server.");
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