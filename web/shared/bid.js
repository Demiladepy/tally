import { load, zec, zip321 } from "./tally.js";

const $ = (id) => document.getElementById(id);
const short = (h) => `${h.slice(0, 10)}…${h.slice(-6)}`;
const SVG = "http://www.w3.org/2000/svg";

const tally = await load(new URL("../tally_wasm.wasm", import.meta.url).href);
const auctionId = new URLSearchParams(location.search).get("auction") ?? "";

let manifest = null;
let bulletinPk = null;
let sealed = null; // { ballot, ballot_sk, P, ballot_hash } — never the bid
let keySaved = false;

function step(n) {
  for (let i = 1; i <= 4; i++) {
    const s = $(`s${i}`);
    s.classList.toggle("done", i < n);
    if (i === n) s.setAttribute("aria-current", "step");
    else s.removeAttribute("aria-current");
  }
}

function status(id, text, kind = "") {
  const s = $(id);
  s.textContent = text;
  s.className = `status ${kind}`;
}

// ---- case file ----
async function loadCase() {
  if (!/^[0-9a-f]{64}$/.test(auctionId)) {
    $("case-label").textContent = "No case selected";
    $("headline").textContent = "Pick an open case first.";
    $("seal-btn").disabled = true;
    return;
  }
  const r = await fetch(`v1/auctions/${auctionId}`);
  if (!r.ok) {
    $("headline").textContent = "That case isn't on this bulletin.";
    $("seal-btn").disabled = true;
    return;
  }
  const log = await r.json();
  manifest = log.manifest;
  bulletinPk = log.bulletin_pk;
  $("verify-link").href = `verify.html?auction=${auctionId}`;
  $("watch").href = `verify.html?auction=${auctionId}`;
  $("case-label").textContent = `Case ${short(auctionId)}`;
  const L = manifest.ladder_zat;
  $("case-facts").textContent =
    `${manifest.supply} item${manifest.supply === 1 ? "" : "s"} · ${L.length} price levels from ${zec(L[0])} to ${zec(L[L.length - 1])} ZEC · ` +
    `bond ${zec(manifest.bond_zat)} ZEC · closes at block ${manifest.close_height} · ${log.entries.length} sealed so far`;
  if (log.close) {
    $("headline").textContent = "This vault is already shut.";
    $("seal-btn").disabled = true;
    status("seal-status", "Bidding closed. Watch the case instead.");
  }
  buildDial(L.length);
  setLevel(Math.ceil(L.length / 2));
}

// ---- dial: 16 notches = 16 price levels ----
function buildDial(levels) {
  const g = $("ticks");
  g.replaceChildren();
  for (let i = 0; i < levels; i++) {
    const a = ((-150 + (300 * i) / (levels - 1)) * Math.PI) / 180;
    const line = document.createElementNS(SVG, "line");
    line.setAttribute("x1", 170 + 136 * Math.sin(a));
    line.setAttribute("y1", 170 - 136 * Math.cos(a));
    line.setAttribute("x2", 170 + 152 * Math.sin(a));
    line.setAttribute("y2", 170 - 152 * Math.cos(a));
    line.setAttribute("stroke-width", "3");
    line.dataset.k = i + 1;
    g.append(line);
  }
  const range = $("range");
  range.max = levels;
}

function setLevel(k) {
  const L = manifest.ladder_zat;
  const range = $("range");
  range.value = k;
  const angle = -150 + (300 * (k - 1)) / (L.length - 1);
  $("knob").style.transform = `rotate(${angle}deg)`;
  for (const t of $("ticks").children) t.setAttribute("stroke", Number(t.dataset.k) <= k ? "#e9ecef" : "#3a4148");
  $("amt").textContent = `${zec(L[k - 1])} ZEC`;
  range.setAttribute("aria-valuetext", `${zec(L[k - 1])} ZEC`);
}

$("range").addEventListener("input", (e) => setLevel(Number(e.target.value)));
// Drag the dial itself.
$("dial").addEventListener("pointerdown", (e) => {
  const dial = $("dial");
  const move = (ev) => {
    const r = dial.getBoundingClientRect();
    const deg = (Math.atan2(ev.clientX - (r.left + r.width / 2), -(ev.clientY - (r.top + r.height / 2))) * 180) / Math.PI;
    const L = manifest.ladder_zat.length;
    const k = Math.round(((Math.max(-150, Math.min(150, deg)) + 150) / 300) * (L - 1)) + 1;
    setLevel(k);
  };
  move(e);
  dial.setPointerCapture(e.pointerId);
  dial.onpointermove = move;
  dial.onpointerup = () => (dial.onpointermove = null);
});

// ---- seal + submit ----
$("seal-btn").addEventListener("click", async () => {
  const btn = $("seal-btn");
  btn.disabled = true;
  status("seal-status", "Sealing in your browser…");
  let maxZat = manifest.ladder_zat[Number($("range").value) - 1];
  try {
    sealed = tally.sealBallot(manifest, maxZat);
  } catch (e) {
    status("seal-status", e.message, "err");
    btn.disabled = false;
    return;
  }
  // The bid has done its job. Drop every trace of it from the page.
  maxZat = null;
  $("range").value = 1;
  $("range").disabled = true;
  $("dial").hidden = true;
  $("readout").hidden = true;
  $("range").hidden = true;
  const env = $("envelope");
  env.hidden = false;
  $("env-contents").textContent = sealed.ballot.c.map((c) => c.A).join(" ");
  requestAnimationFrame(() => requestAnimationFrame(() => env.classList.add("sealed")));
  step(2);
  $("stage-title").textContent = "Sealed. Slipping it under the door…";
  $("stage-body").textContent = `${sealed.levels_sealed} encrypted yes/no cells, each with a proof it holds 0 or 1, plus proofs the cells only step down.`;

  try {
    const r = await fetch(`v1/auctions/${auctionId}/ballots`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sealed.ballot),
    });
    if (!r.ok) throw new Error(r.status === 409 ? "The bulletin is closed or saw this key already." : `Bulletin refused the ballot (HTTP ${r.status}).`);
    sealed.receipt = await r.json();
    if (!tally.verifyReceipt(sealed.receipt, bulletinPk, auctionId)) throw new Error("Receipt signature is invalid. Keep your key and report this.");
  } catch (e) {
    status("seal-status", e.message, "err");
    return;
  }
  $("stage-title").textContent = `On the books as ballot #${sealed.receipt.i}.`;
  status("seal-status", "Receipt verified: signed by the bulletin.", "ok");
  btn.hidden = true;
  renderReceipt();
  step(3);
  $("stage-bond").hidden = false;
  $("stage-bond").scrollIntoView({ behavior: "smooth", block: "start" });
});

window.addEventListener("beforeunload", (e) => {
  if (sealed?.receipt && !keySaved) e.preventDefault();
});

// ---- bond ----
$("bond-btn").addEventListener("click", () => {
  const refund = $("refund").value.trim();
  if (!/^(utest1|u1)[0-9a-z]{50,}$/.test(refund)) {
    status("bond-status", "Paste a unified address (starts with utest1 on testnet).", "err");
    $("refund").setAttribute("aria-invalid", "true");
    return;
  }
  $("refund").removeAttribute("aria-invalid");
  let memo;
  try {
    memo = tally.bondMemo(auctionId, sealed.ballot_hash, refund);
  } catch (e) {
    status("bond-status", e.message, "err");
    return;
  }
  const uri = zip321(manifest.escrow_ua, manifest.bond_zat, memo.hex);
  $("memo-text").textContent = memo.text;
  $("escrow-addr").textContent = manifest.escrow_ua;
  $("uri").textContent = uri;
  $("open-wallet").href = uri;
  $("bond-out").hidden = false;
  status("bond-status", `${zec(manifest.bond_zat)} ZEC to the escrow.`, "ok");
});

for (const [btn, src] of [["copy-memo", "memo-text"], ["copy-addr", "escrow-addr"]]) {
  $(btn).addEventListener("click", async () => {
    await navigator.clipboard.writeText($(src).textContent);
    $(btn).textContent = "Copied";
  });
}

$("copy-uri").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("uri").textContent);
  $("copy-uri").textContent = "Copied";
});

$("bond-done").addEventListener("click", () => {
  step(4);
  $("stage-key").hidden = false;
  $("stage-key").scrollIntoView({ behavior: "smooth", block: "start" });
});

// ---- key ----
function renderReceipt() {
  const ul = $("receipt");
  ul.replaceChildren();
  for (const [k, v] of [
    ["Ballot #", String(sealed.receipt.i)],
    ["Ballot ID", short(sealed.P)],
    ["Entry hash", short(sealed.receipt.entry_hash)],
  ]) {
    const li = document.createElement("li");
    const a = document.createElement("span");
    a.className = "label";
    a.textContent = k;
    const b = document.createElement("span");
    b.className = "hash";
    b.textContent = v;
    li.append(a, b);
    ul.append(li);
  }
}

$("key-btn").addEventListener("click", () => {
  // Same shape as `tally-settle bid` records, so `sale-build --claim` accepts it.
  const key = {
    auction_id: auctionId,
    bulletin: location.origin,
    account: "browser",
    P: sealed.P,
    ballot_sk: sealed.ballot_sk,
    ballot_hash: sealed.ballot_hash,
    receipt: sealed.receipt,
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(key, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `tally-bid-${auctionId.slice(0, 8)}-${sealed.receipt.i}.json`;
  a.click();
  URL.revokeObjectURL(url);
  keySaved = true;
  $("key-btn").textContent = "Key saved";
});

loadCase();
