// Loader for tally_wasm.wasm (plain C ABI, JSON in/out). Works in browsers
// and in Node. The module imports nothing from the host.

let wasm = null;

export async function load(source) {
  // source: URL string (browser) or bytes (Node / tests).
  const bytes = typeof source === "string" ? await (await fetch(source)).arrayBuffer() : source;
  const { instance } = await WebAssembly.instantiate(bytes, {});
  wasm = instance.exports;
  return api;
}

function call(fn, input) {
  if (!wasm) throw new Error("tally wasm not loaded");
  const data = new TextEncoder().encode(JSON.stringify(input));
  const ptr = wasm.tally_alloc(data.length);
  new Uint8Array(wasm.memory.buffer, ptr, data.length).set(data);
  wasm[fn](ptr, data.length); // takes ownership of the input buffer
  const out = new Uint8Array(wasm.memory.buffer, wasm.tally_out_ptr(), wasm.tally_out_len());
  const reply = JSON.parse(new TextDecoder().decode(out));
  if ("err" in reply) throw new Error(reply.err);
  return reply.ok;
}

function seedHex() {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export const api = {
  /** Every public check on an auction log object. */
  verifyLog: (log) => call("tally_verify_log", log),
  /** Seal a ballot. The bid is used inside WASM and never returned. */
  sealBallot: (manifest, maxPriceZat) =>
    call("tally_seal_ballot", { manifest, max_price_zat: maxPriceZat, seed_hex: seedHex() }),
  /** Bond memo: { text, hex }. Text so any wallet can send it. */
  bondMemo: (auctionId, ballotHash, refundUa) =>
    call("tally_bond_memo", { auction_id: auctionId, ballot_hash: ballotHash, refund_ua: refundUa }),
  /** Bulletin's signed inclusion receipt. */
  verifyReceipt: (receipt, bulletinPk, auctionId) =>
    call("tally_verify_receipt", { receipt, bulletin_pk: bulletinPk, auction_id: auctionId }),
  /** Win claim over a listing hash. */
  signClaim: (ballotSk, listingHash) =>
    call("tally_sign_claim", { ballot_sk: ballotSk, listing_hash: listingHash, seed_hex: seedHex() }),
};

/** ZIP 321 payment URI with a binary memo (base64url, no padding). */
export function zip321(address, zat, memoHex) {
  const bytes = memoHex.match(/../g).map((h) => parseInt(h, 16));
  // Trailing zero padding is implied (ZIP 302/321): the wallet re-pads to 512.
  while (bytes.length && bytes[bytes.length - 1] === 0) bytes.pop();
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  const b64 = btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const amount = (zat / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
  return `zcash:${address}?amount=${amount}&memo=${b64}`;
}

export const zec = (zat) => (zat / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
