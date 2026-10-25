// node web/test/wasm.test.mjs <path/to/tally_wasm.wasm>
// Runs the browser verifier on the real testnet auction log, then tampers.
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { load, zip321 } from "../shared/tally.js";

const wasmPath = process.argv[2] ?? "web/tally_wasm.wasm";
const t = await load(await readFile(wasmPath));
const log = JSON.parse(await readFile(new URL("../../evidence/testnet-2026-10-22-auction/auction-log.json", import.meta.url)));
// Public test data from `cargo run -p tally-wasm --example web_test_fixtures`.
const fx = JSON.parse(await readFile(new URL("./fixtures.json", import.meta.url)));

// 1. The testnet auction goes all green in WASM.
const r = t.verifyLog(log);
for (const c of r.checks) console.log(`${c.ok ? "PASS" : "FAIL"} ${c.name}: ${c.detail}`);
assert.equal(r.checks.length, 10);
assert.ok(r.all_ok, "testnet log must verify");
assert.equal(r.summary.result.price_zat, 1200000);
assert.deepEqual([...r.summary.decrypted_totals].sort((a, b) => a - b), [8, 12, 13, 14]);

// 2. Tampering turns it red.
const red = (mutate, name) => {
  const l = structuredClone(log);
  mutate(l);
  const v = t.verifyLog(l);
  assert.ok(!v.all_ok, `tamper not caught: ${name}`);
  console.log(`caught: ${name} -> ${v.checks.find((c) => !c.ok).name}`);
};
red((l) => (l.result.price_zat = 1100000), "lower clearing price");
red((l) => l.result.winners.reverse() && (l.result.winners[0] = l.entries[0].ballot.P), "swap a winner");
red((l) => (l.decryptions[0].m += 1), "forge a decrypted total");
red((l) => l.decryptions.pop(), "hide a decryption");
red((l) => (l.entries[1].ballot.c[3] = l.entries[2].ballot.c[3]), "alter a ballot");
red((l) => l.entries.pop(), "drop a ballot");
red((l) => l.bonds.sigs.pop(), "break the bond quorum");
red((l) => (l.manifest.supply = 3), "change supply");
red((l) => (l.settlements[0].txid = "00".repeat(32)), "forge a settlement");

// 3. Sealing a ballot in WASM produces something the verifier side accepts,
//    and the output never contains the bid. The testnet log is legacy v1:
//    it still verifies, but takes no new ballots.
assert.throws(() => t.sealBallot(log.manifest, 700000), /legacy v1/);
const m = fx.manifest_v2;
const unendorsed = structuredClone(m);
unendorsed.endorsements.pop();
assert.throws(() => t.sealBallot(unendorsed, 700000), /endorsed/);
const swapped = structuredClone(m);
swapped.escrow_ua = fx.orchard_only_ua;
assert.throws(() => t.sealBallot(swapped, 700000), /manifest rejected/);
const sealed = t.sealBallot(m, 700000);
assert.equal(sealed.levels_sealed, 16);
assert.ok(!JSON.stringify(sealed).includes("700000"), "bid leaked into output");
assert.equal(sealed.ballot.c.length, 16);
assert.throws(() => t.sealBallot(m, 50000), /below the lowest/);
// A real Orchard-only testnet UA, and one that also carries a transparent
// receiver, which must be refused.
const ORCHARD_ONLY = fx.orchard_only_ua;
const WITH_T = fx.with_transparent_ua;
assert.throws(() => t.bondMemo(m.auction_id, sealed.ballot_hash, WITH_T), /only an Orchard receiver/);
assert.throws(() => t.bondMemo(m.auction_id, sealed.ballot_hash, "utest1" + "q".repeat(100)), /only an Orchard receiver/);
const memo = t.bondMemo(m.auction_id, sealed.ballot_hash, ORCHARD_ONLY);
assert.equal(memo.hex.length, 1024);
assert.ok(memo.text.startsWith(`TLYB1 ${m.auction_id} ${sealed.ballot_hash} utest1`), "plain-text bond memo");
assert.ok(/^[\x20-\x7e]+$/.test(memo.text), "printable ASCII only");
const claim = t.signClaim(sealed.ballot_sk, "ab".repeat(32));
assert.equal(claim.P, sealed.P);
// The ZIP 321 URI trims zero padding; re-padded, it must be the same memo.
const uri = zip321("utest1escrow", 100000, memo.hex);
const b64 = new URL(uri.replace("zcash:", "zcash://x/")).searchParams.get("memo");
const raw = Buffer.from(b64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
assert.ok(raw.length < 512, "padding trimmed");
const padded = Buffer.concat([raw, Buffer.alloc(512 - raw.length)]);
assert.equal(padded.toString("hex"), memo.hex);
assert.equal(raw.toString("utf8"), memo.text, "URI memo is exactly the text");
assert.ok(uri.includes("amount=0.001&"));
console.log("seal, bond memo, ZIP 321 round trip, claim: ok");
console.log("ALL WASM TESTS PASSED");
