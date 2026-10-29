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
  data.fill(0); // the copy WASM got is wiped there after use
  wasm[fn](ptr, data.length); // takes ownership of the input buffer
  const out = new Uint8Array(wasm.memory.buffer, wasm.tally_out_ptr(), wasm.tally_out_len());
  const reply = JSON.parse(new TextDecoder().decode(out));
  wasm.tally_clear_out(); // the reply can hold a ballot key
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
  /** Seller: draft and sign an offering. Returns { draft, seller_key }. */
  draftOffering: (terms) => call("tally_draft_offering", { ...terms, seed_hex: seedHex() }),
  /** Seller: attach endorsements; returns the publishable manifest. */
  attachEndorsements: (draft, endorsements) => call("tally_attach_endorsements", { draft, endorsements }),
  /** Seller: sign the close of the log at its current head. */
  signClose: (sellerSk, log) => call("tally_sign_close", { seller_sk: sellerSk, log, seed_hex: seedHex() }),
  /** QR code (SVG string) for a payment request. */
  qrSvg: (text) => call("tally_qr_svg", { text }),
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

/** The desk's view of the chain tip, or null if it doesn't track one. */
export async function chainTip() {
  const r = await fetch("v1/chain").catch(() => null);
  return r?.ok ? r.json() : null;
}

/** "2,345 blocks (≈ 14 h)" — time only when the desk has measured the pace. */
export function blocksLeft(n, tip) {
  const blocks = `${n.toLocaleString("en-US")} block${n === 1 ? "" : "s"}`;
  if (!tip?.secs_per_block) return blocks;
  const s = n * tip.secs_per_block;
  const t = s < 3600 ? `${Math.max(1, Math.round(s / 60))} min` : s < 172800 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} days`;
  return `${blocks} (≈ ${t} at the current pace)`;
}

export const zec = (zat) => (zat / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
