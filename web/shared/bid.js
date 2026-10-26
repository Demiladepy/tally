import { load, zec, zip321 } from "./tally.js";

const $ = (id) => document.getElementById(id);
const short = (h) => `${h.slice(0, 8)}…${h.slice(-6)}`;
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

const tally = await load(new URL("../tally_wasm.wasm", import.meta.url).href);
const auctionId = new URLSearchParams(location.search).get("auction") ?? "";

let manifest = null;
let bulletinPk = null;
let sealed = null; // { ballot, ballot_sk, P, ballot_hash, receipt } — never the limit
let keySaved = false;

function status(id, text, kind = "") {
  const s = $(id);
  s.textContent = text;
  s.className = `status ${kind}`;
}
function show(panel) {
  for (const id of ["t-enter", "t-review", "t-track"]) $(id).hidden = id !== panel;
}
function setState(text, kind) {
  $("state").textContent = text;
  $("state").className = `pill ${kind ?? ""}`;
}
function blockTicket(text) {
  $("review-btn").disabled = true;
  status("enter-status", text, "err");
}

// ---- tabs ----
for (const b of document.querySelectorAll("[data-tab]")) {
  b.addEventListener("click", () => {
    for (const x of document.querySelectorAll("[data-tab]")) x.setAttribute("aria-selected", String(x === b));
    for (const p of document.querySelectorAll("[data-panel]")) p.hidden = p.dataset.panel !== b.dataset.tab;
  });
}

// ---- offering ----
function term(dl, k, v, mono = true) {
  dl.append(el("dt", "", k), el("dd", mono ? "mono" : "", v));
}

async function loadOffering() {
  if (!/^[0-9a-f]{64}$/.test(auctionId)) {
    $("title").textContent = "No offering selected";
    $("subtitle").textContent = "Pick one from the Offerings list.";
    return blockTicket("Pick an offering first.");
  }
  const r = await fetch(`v1/auctions/${auctionId}`);
  if (!r.ok) {
    $("title").textContent = "Offering not found on this desk";
    return blockTicket("This desk doesn't list that offering.");
  }
  const log = await r.json();
  // The link names the auction id, and in v2 the id is the hash of the
  // manifest's contents (WASM re-checks that, and every endorsement, before
  // sealing). A desk serving some other manifest is refused here.
  if (log.manifest?.auction_id !== auctionId || log.manifest.v < 2) {
    $("title").textContent = "This offering doesn't match its link";
    setState("Do not trade", "bad");
    return blockTicket("The terms served don't hash to this offering's ID. Don't place an order.");
  }
  manifest = log.manifest;
  bulletinPk = log.bulletin_pk;
  const m = manifest;
  const L = m.ladder_zat;
  $("report-nav").href = `verify.html?auction=${auctionId}`;
  $("crumb").textContent = `Block sale ${short(auctionId)}`;
  $("title").textContent = `Block sale ${short(auctionId)}`;
  $("subtitle").textContent = `Uniform-price sealed-bid sale of ${m.supply} unit${m.supply === 1 ? "" : "s"} · closes at block ${m.close_height.toLocaleString("en-US")}`;
  $("k-units").textContent = String(m.supply);
  $("k-range").replaceChildren(`${zec(L[0])} – ${zec(L[L.length - 1])}`, el("small", "", " ZEC"));
  $("k-dep").replaceChildren(zec(m.bond_zat), el("small", "", " ZEC"));
  $("k-orders").textContent = String(log.entries.length);

  const dl = $("terms");
  term(dl, "Offering ID", auctionId);
  term(dl, "Instrument", `Tally item, collection ${short(m.collection_id)}`, false);
  term(dl, "Units offered", String(m.supply));
  term(dl, "Price ladder", `${L.length} levels, ${zec(L[0])} to ${zec(L[L.length - 1])} ZEC in steps of ${zec(L[1] - L[0])}`);
  term(dl, "Pricing", "Uniform clearing price; ties broken by a public seed", false);
  term(dl, "Refundable deposit", `${zec(m.bond_zat)} ZEC per order`);
  term(dl, "Minimum book size", `${m.min_batch} funded orders, else void and refunded`);
  term(dl, "Order window", `blocks ${m.open_height.toLocaleString("en-US")} – ${m.close_height.toLocaleString("en-US")}`);
  term(dl, "Settlement window", `${m.settle_window_blocks} blocks after close`);
  term(dl, "Settlement", "Delivery-versus-payment in one shielded Ironwood transaction", false);
  term(dl, "Clearing committee", `${m.committee.t}-of-${m.committee.n} threshold`);
  term(dl, "Deposit escrow", m.escrow_ua);

  const mini = $("ladder-mini");
  mini.style.setProperty("--n", L.length);
  mini.replaceChildren(...L.map(() => el("i")));
  $("lad-lo").textContent = zec(L[0]);
  $("lad-hi").textContent = zec(L[L.length - 1]);

  const members = $("members");
  m.committee.members.forEach((name, i) => {
    const j = i + 1;
    const row = el("div", "member");
    const who = el("div", "who");
    who.append(el("b", "", name), el("small", "", `member ${j} · key ${short(String(m.committee.X[i]))}`));
    const endorsed = (m.endorsements ?? []).some((e) => e.j === j);
    row.append(el("span", "av", name.trim()[0]?.toUpperCase() ?? "?"), who, el("span", endorsed ? "check" : "pill bad", endorsed ? "✓ Co-signed" : "Missing"));
    members.append(row);
  });

  const book = $("book");
  if (!log.entries.length) {
    const tr = el("tr");
    const td = el("td", "empty", "No orders yet. The book shows only ciphertext, never limits.");
    td.colSpan = 4;
    tr.append(td);
    book.append(tr);
  }
  for (const e of log.entries) {
    const tr = el("tr");
    tr.append(el("td", "num", String(e.i)), el("td", "mono", short(e.ballot.P)), el("td", "mono", short(e.entry_hash)), el("td", "mono faint", `${e.ballot.c.length} encrypted cells`));
    book.append(tr);
  }

  if (log.close) {
    setState(log.result ? "Cleared" : "Closed · clearing", "wait");
    return blockTicket("The order window has closed. See the clearing report.");
  }
  setState("Open for orders");

  // Ticket: the limit is a ladder level.
  const sel = $("limit");
  sel.replaceChildren(...L.map((p, i) => Object.assign(el("option", "", zec(p)), { value: String(i + 1) })));
  sel.value = String(Math.ceil(L.length / 2));
  const quick = $("quick");
  for (const [label, k] of [["Floor", 1], ["Mid", Math.ceil(L.length / 2)], ["Ceiling", L.length]]) {
    const b = el("button", "", `${label} ${zec(L[k - 1])}`);
    b.type = "button";
    b.addEventListener("click", () => setLevel(k));
    quick.append(b);
  }
  $("sum-dep").textContent = `${zec(m.bond_zat)} ZEC`;
  setLevel(Number(sel.value));
}

function level() {
  return Number($("limit").value);
}
function setLevel(k) {
  const L = manifest.ladder_zat;
  k = Math.max(1, Math.min(L.length, k));
  $("limit").value = String(k);
  $("sum-max").textContent = `${zec(L[k - 1] + manifest.bond_zat)} ZEC`;
}
$("limit").addEventListener("change", () => setLevel(level()));
$("dec").addEventListener("click", () => manifest && setLevel(level() - 1));
$("inc").addEventListener("click", () => manifest && setLevel(level() + 1));

// ---- review ----
$("review-btn").addEventListener("click", () => {
  if (!manifest) return;
  $("rv-off").textContent = short(auctionId);
  $("rv-limit").textContent = `${zec(manifest.ladder_zat[level() - 1])} ZEC`;
  $("rv-dep").textContent = `${zec(manifest.bond_zat)} ZEC`;
  show("t-review");
});
$("back-btn").addEventListener("click", () => show("t-enter"));

// ---- seal + submit ----
$("seal-btn").addEventListener("click", async () => {
  const btn = $("seal-btn");
  btn.disabled = true;
  $("back-btn").disabled = true;
  status("seal-status", "Encrypting in your browser…");
  let maxZat = manifest.ladder_zat[level() - 1];
  try {
    sealed = tally.sealBallot(manifest, maxZat);
  } catch (e) {
    status("seal-status", e.message, "err");
    btn.disabled = false;
    $("back-btn").disabled = false;
    return;
  }
  // The limit has done its job. Remove every trace of it from the page.
  maxZat = null;
  $("limit").replaceChildren();
  $("quick").replaceChildren();
  $("sum-max").textContent = "—";
  $("rv-limit").textContent = "sealed";
  status("seal-status", "Submitting ciphertext to the desk…");

  try {
    const r = await fetch(`v1/auctions/${auctionId}/ballots`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sealed.ballot),
    });
    if (!r.ok) throw new Error(r.status === 409 ? "The order window is closed, or this order was already submitted." : `The desk refused the order (HTTP ${r.status}).`);
    sealed.receipt = await r.json();
    if (!tally.verifyReceipt(sealed.receipt, bulletinPk, auctionId)) throw new Error("The receipt signature is invalid. Keep your key and report this.");
  } catch (e) {
    status("seal-status", e.message, "err");
    return;
  }
  const kv = $("receipt");
  for (const [k, v] of [["Order #", String(sealed.receipt.i)], ["Order ID", short(sealed.P)], ["Entry hash", short(sealed.receipt.entry_hash)], ["Cells sealed", String(sealed.levels_sealed)]]) {
    kv.append(el("span", "", k), el("span", "", v));
  }
  $("k-orders").textContent = String(sealed.receipt.i + 1);
  show("t-track");
});

window.addEventListener("beforeunload", (e) => {
  if (sealed?.receipt && !keySaved) e.preventDefault();
});

// ---- deposit ----
$("bond-btn").addEventListener("click", () => {
  const refund = $("refund").value.trim();
  if (!/^(utest1|u1)[0-9a-z]{50,}$/.test(refund)) {
    status("bond-status", "Paste a unified address (utest1… on testnet).", "err");
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
  $("dep-form").hidden = true;
  $("bond-out").hidden = false;
});

for (const [btn, src] of [["copy-memo", "memo-text"], ["copy-addr", "escrow-addr"], ["copy-uri", "uri"]]) {
  $(btn).addEventListener("click", async () => {
    await navigator.clipboard.writeText($(src).textContent);
    $(btn).textContent = "Copied";
  });
}

$("bond-done").addEventListener("click", () => {
  $("tr2").className = "done";
  $("tr2").querySelector(".dot").textContent = "✓";
  $("bond-out").hidden = true;
  $("tr3").className = "now";
  $("key-box").hidden = false;
});

// ---- key ----
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
  // A generic name: the file list on a seized or synced machine shouldn't
  // say which offering or order number this was.
  a.download = "tally-key.json";
  a.click();
  URL.revokeObjectURL(url);
  keySaved = true;
  $("key-btn").textContent = "Key saved";
  $("tr3").className = "done";
  $("tr3").querySelector(".dot").textContent = "✓";
});

loadOffering();
