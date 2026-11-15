"use strict";
// zkVerify Agent Games - Proof Gatekeeper agent endpoint.
// Plain (req,res) handler: works on Vercel (@vercel/node) and behind the
// local runner (server.mjs). No framework, only snarkjs.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ---------- config ----------
function secretBytes() {
  const raw = (process.env.AGENT_HMAC_SECRET || "").trim();
  if (!raw) return null;
  return Buffer.from(raw, "utf8");
}

function circuitPaths() {
  const names = ["gatekeeper.wasm", "gatekeeper_final.zkey"];
  const roots = [
    process.cwd(),
    path.join(process.cwd(), "circuits"),
    path.join(__dirname, ".."),
    path.join(__dirname, "..", "circuits"),
    __dirname,
    "/var/task",
    "/var/task/circuits",
    "/var/task/user",
    "/var/task/user/circuits",
  ];
  for (const r of roots) {
    const w = path.join(r, names[0]);
    const z = path.join(r, names[1]);
    if (fs.existsSync(w) && fs.existsSync(z)) return { wasm: w, zkey: z };
  }
  return { wasm: path.join(process.cwd(), names[0]), zkey: path.join(process.cwd(), names[1]) };
}

// ---------- tiny KV (Upstash REST if configured, else in-memory) ----------
const mem = new Map();
async function kvGet(key) {
  const url = process.env.UPSTASH_REDIS_REST_URL, tok = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (url && tok) {
    try {
      const r = await fetch(`${url}/get/${encodeURIComponent(key)}`, { headers: { Authorization: `Bearer ${tok}` } });
      const j = await r.json();
      return j.result ?? null;
    } catch (e) { /* fall through to memory */ }
  }
  return mem.has(key) ? mem.get(key) : null;
}
async function kvSet(key, val) {
  mem.set(key, val);
  const url = process.env.UPSTASH_REDIS_REST_URL, tok = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (url && tok) {
    try {
      await fetch(`${url}/set/${encodeURIComponent(key)}/${encodeURIComponent(val)}`, { headers: { Authorization: `Bearer ${tok}` } });
    } catch (e) { /* memory copy already kept */ }
  }
}

// ---------- helpers ----------
function hmacHex(secret, buf) {
  return crypto.createHmac("sha256", secret).update(buf).digest("hex");
}
function sigOk(secret, headerVal, rawBody) {
  if (!secret || !headerVal) return false;
  const expected = hmacHex(secret, rawBody);
  const got = String(headerVal).trim().replace(/^sha256=/i, "").toLowerCase();
  if (got.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(got, "utf8"), Buffer.from(expected, "utf8")); }
  catch (e) { return false; }
}
function toBig(x) {
  if (x === null || x === undefined) return null;
  const s = String(x).trim();
  try { return BigInt(s); } catch (e) { return null; }
}
function taskIdField(taskId) {
  const m = String(taskId).match(/(\d+)/);
  if (m) return BigInt(m[1]);
  const h = crypto.createHash("sha256").update(String(taskId)).digest("hex");
  return BigInt("0x" + h) % FR;
}
function saltFor(secret, taskId) {
  const h = crypto.createHash("sha256")
    .update(secret || Buffer.alloc(0)).update(":").update(String(taskId)).digest("hex");
  return (BigInt("0x" + h) % FR).toString();
}

// Evaluate the field checks. Returns {decision, reason} where reason is the
// provable trap code, or null when every field check passes.
function evaluate(inp) {
  const regVk = toBig(inp.registered_vk), proofVk = toBig(inp.proof_vk);
  if (regVk === null || proofVk === null || regVk % FR !== proofVk % FR) return { decision: "REJECT", reason: "VK_SUBSTITUTION" };
  const bal = toBig(inp.public_balance), min = toBig(inp.minimum);
  if (bal === null || min === null || bal < min) return { decision: "REJECT", reason: "THRESHOLD_MISMATCH" };
  const cur = toBig(inp.current_block), exp = toBig(inp.expiry_block);
  if (cur === null || exp === null || cur > exp) return { decision: "REJECT", reason: "EXPIRED_CONDITION" };
  const rec = toBig(inp.recipient), crec = toBig(inp.condition_recipient);
  if (rec === null || crec === null || rec !== crec) return { decision: "REJECT", reason: "RECIPIENT_MISMATCH" };
  const amt = toBig(inp.amount), cap = toBig(inp.max_transfer);
  if (amt === null || cap === null || amt > cap) return { decision: "REJECT", reason: "AMOUNT_OVERFLOW" };
  return { decision: "APPROVE", reason: "VALID_CONDITION" };
}

function circuitInput(task, decisionNum, secret) {
  const inp = task.input;
  return {
    taskId: taskIdField(task.task_id).toString(),
    minimum: String(inp.minimum),
    publicBalance: String(inp.public_balance),
    expiryBlock: String(inp.expiry_block),
    currentBlock: String(inp.current_block),
    recipient: toBig(inp.recipient).toString(),
    conditionRecipient: toBig(inp.condition_recipient).toString(),
    amount: String(inp.amount),
    maxTransfer: String(inp.max_transfer),
    registeredVkHash: toBig(inp.registered_vk).toString(),
    proofVkHash: toBig(inp.proof_vk).toString(),
    salt: saltFor(secret, task.task_id),
    decision: String(decisionNum),
  };
}

async function prove(task, decisionNum, secret) {
  const { wasm, zkey } = circuitPaths();
  const input = circuitInput(task, decisionNum, secret);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
  return { proof, publicSignals };
}

// ---------- main handler ----------
module.exports = async (req, res) => {
  const send = (code, obj, secret) => {
    const body = Buffer.from(JSON.stringify(obj), "utf8");
    const headers = { "Content-Type": "application/json" };
    if (secret) headers["x-agent-games-signature"] = hmacHex(secret, body);
    res.writeHead(code, headers);
    res.end(body);
  };
  try {
    if (req.method === "GET") {
      return send(200, { ok: true, protocolVersion: "v1" }, secretBytes());
    }
    if (req.method !== "POST") return send(405, { error: "method_not_allowed" }, null);

    const chunks = [];
    for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks);
    const secret = secretBytes();

    // HMAC first, before parsing (rules 1.3). If no secret configured yet,
    // accept unsigned only when ALLOW_UNSIGNED=1 (local testing).
    const sig = req.headers["x-agent-games-signature"];
    if (process.env.ALLOW_UNSIGNED !== "1") {
      if (!sigOk(secret, sig, raw))         return send(401, { error: "bad_signature" }, null);
    }

    let task;
    try { task = JSON.parse(raw.toString("utf8")); }
    catch (e) { return send(400, { error: "bad_json" }, secret); }

    console.log("TASK", JSON.stringify(task).slice(0, 2000));

    if (!task || typeof task !== "object" || !task.input || !task.task_id) {
      // Health / preflight style ping without a task payload.
      return send(200, { ok: true, protocolVersion: "v1" }, secret);
    }

    const mode = task.mode === "practice" ? "practice" : "competition";
    const respKey = `gk:resp:${mode}:${task.task_id}`;
    const cached = await kvGet(respKey);
    if (cached) {
      const body = Buffer.from(cached, "utf8");
      const headers = { "Content-Type": "application/json" };
      if (secret) headers["x-agent-games-signature"] = hmacHex(secret, body);
      res.writeHead(200, headers);
      return res.end(body);
    }

    const inp = task.input;
    const proofTx = String(inp.proof_tx || "");
    const seenKey = `gk:seen:${mode}:${proofTx.toLowerCase()}`;
    const seenBy = proofTx ? await kvGet(seenKey) : null;
    const isReused = !!(seenBy && seenBy !== String(task.task_id));

    const ev = evaluate(inp);
    let out;
    if (ev.decision === "REJECT" && ev.reason !== "VALID_CONDITION") {
      // Provable rejection for a field trap (takes priority over reuse).
      try {
        const { proof, publicSignals } = await prove(task, 0, secret);
        out = { decision: "REJECT", reason_code: ev.reason, proof_tx: inp.proof_tx, proof, public_signals: publicSignals };
      } catch (e) {
        console.log("PROVE_REJECT_FAILED", String(e).split("\n")[0]);
        out = { decision: "REJECT", reason_code: ev.reason, proof_tx: inp.proof_tx };
      }
    } else if (isReused) {
      // Reused proof: the circuit cannot certify this rejection; answer
      // without a proof (scoring excludes these tasks from the proof bonus).
      out = { decision: "REJECT", reason_code: "PROOF_REUSED", proof_tx: inp.proof_tx };
    } else {
      try {
        const { proof, publicSignals } = await prove(task, 1, secret);
        out = { decision: "APPROVE", reason_code: "VALID_CONDITION", proof_tx: inp.proof_tx, proof, public_signals: publicSignals };
      } catch (e) {
        // Circuit refused approval: our evaluation missed something.
        // Fall back to a provable rejection if possible.
        console.log("PROVE_APPROVE_FAILED", String(e).split("\n")[0]);
        try {
          const { proof, publicSignals } = await prove(task, 0, secret);
          out = { decision: "REJECT", reason_code: ev.reason === "VALID_CONDITION" ? "THRESHOLD_MISMATCH" : ev.reason, proof_tx: inp.proof_tx, proof, public_signals: publicSignals };
        } catch (e2) {
          out = { decision: "REJECT", reason_code: "PROOF_INVALID", proof_tx: inp.proof_tx };
        }
      }
    }

    if (proofTx) await kvSet(seenKey, String(task.task_id));
    const bodyStr = JSON.stringify(out);
    await kvSet(respKey, bodyStr);
    const body = Buffer.from(bodyStr, "utf8");
    const headers = { "Content-Type": "application/json" };
    if (secret) headers["x-agent-games-signature"] = hmacHex(secret, body);
    res.writeHead(200, headers);
    return res.end(body);
  } catch (e) {
    console.log("HANDLER_ERROR", e && e.stack ? e.stack.split("\n").slice(0, 3).join(" | ") : String(e));
    // Fail closed: still answer so the platform does not record a timeout.
    try { return send(200, { decision: "REJECT", reason_code: "INTERNAL_ERROR" }, secretBytes()); }
    catch (e2) { res.writeHead(500); return res.end("{}"); }
  }
};
