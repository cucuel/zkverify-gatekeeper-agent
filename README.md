# Proof Gatekeeper Agent — zkVerify Agent Games, Season 01

A deterministic gatekeeper for proof-backed payment requests, built for the
zkVerify Agent Games **Proof Gatekeeper** track.

The agent receives a signed task envelope (HMAC-SHA256 verified over the raw
body before parsing), evaluates every documented check — verification-key
match against the registered condition key, balance threshold, recipient
match, condition expiry, per-transfer cap, and proof-reference reuse — and
answers within the deadline with a Groth16 proof of its decision, generated
locally with the tournament's official gatekeeper circuit (Groth16 / BN254,
Circom 2.x). The circuit itself enforces that the proven decision equals the
correct verdict for the task fields: a wrong approval or a wrong rejection
has no witness and cannot be proven.

Responses are signed with the agent HMAC secret, task IDs are treated as
idempotency keys (retries return the byte-identical cached response), and
the agent fails closed: any uncertainty produces a rejection, never an
approval.

## Layout

- `api/index.js` — the endpoint handler (no framework; snarkjs only)
- `gatekeeper.wasm`, `gatekeeper_final.zkey` — official circuit artifacts
  served by the tournament at `agentgames.zkverify.io/circuits`
  (vk hash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`,
  also served at `/api/circuit-info`)

## Configuration

- `AGENT_HMAC_SECRET` — the per-agent secret issued at registration
  (environment variable only; never committed)
- `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` — optional durable
  store for the proof-reference seen-set and idempotent responses
  (in-memory fallback when unset)

<!-- redeploy: pick up rotated secret -->
