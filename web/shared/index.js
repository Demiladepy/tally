import { zec } from "./tally.js";

const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === "class" ? (n.className = v) : n.setAttribute(k, v);
  for (const c of kids) n.append(c);
  return n;
};
const short = (h) => `${h.slice(0, 6)}…${h.slice(-4)}`;

// The hero texture is real ciphertext: ballot cells from the order book.
function paintCipher(log) {
  const hex = (log?.entries ?? []).flatMap((e) => e.ballot.c.flatMap((c) => [c.A, c.B])).filter((x) => typeof x === "string").join("");
  if (!hex) return;
  let s = hex;
  while (s.length < 24000) s += hex;
  $("cipher").textContent = s.slice(0, 24000);
}

function row(a, log) {
  const L = log?.manifest?.ladder_zat;
  const status = a.cleared ? el("span", { class: "pill" }, "Cleared") : a.closed ? el("span", { class: "pill wait" }, "Clearing") : el("span", { class: "pill open" }, "Open");
  const action = a.closed
    ? el("a", { class: "btn sm", href: `verify.html?auction=${a.auction_id}` }, "Clearing report")
    : el("a", { class: "btn sm cta", href: `bid.html?auction=${a.auction_id}` }, "Place order");
  return el("tr", {},
    el("td", {}, el("div", { class: "asset" }, el("span", { class: "glyph" }, a.auction_id.slice(0, 2).toUpperCase()),
      el("div", {}, el("b", {}, log?.manifest?.title || `Block sale ${short(a.auction_id)}`), el("small", {}, `${short(a.auction_id)} · ${a.levels}-level ladder · uniform price`)))),
    el("td", { class: "r num" }, String(a.supply)),
    el("td", { class: "r num col-hide" }, L ? `${zec(L[0])} – ${zec(L[L.length - 1])}` : "—"),
    el("td", { class: "r num col-hide" }, log ? zec(log.manifest.bond_zat) : "—"),
    el("td", { class: "r num" }, String(a.ballots)),
    el("td", {}, status),
    el("td", { class: "r" }, action));
}

try {
  const auctions = (await (await fetch("v1/auctions")).json()).reverse();
  const logs = await Promise.all(auctions.map((a) => fetch(`v1/auctions/${a.auction_id}`).then((r) => r.json()).catch(() => null)));
  const tbody = $("rows");
  tbody.replaceChildren();
  $("count").textContent = `${auctions.length} on this desk`;
  $("st-open").textContent = String(auctions.filter((a) => !a.closed).length);
  $("st-orders").textContent = String(auctions.reduce((n, a) => n + a.ballots, 0));
  if (!auctions.length) tbody.append(el("tr", {}, el("td", { colspan: "7", class: "empty" }, "No offerings on this desk yet.")));
  auctions.forEach((a, i) => tbody.append(row(a, logs[i])));
  const withOrders = logs.find((l) => l?.entries?.length);
  if (withOrders) paintCipher(withOrders);
  else paintCipher(await fetch("samples/testnet-2026-10-22.json").then((r) => r.json()).catch(() => null));
} catch {
  // Static hosting (GitHub Pages): no live desk, but the recorded testnet
  // auction's clearing report still verifies entirely in the browser.
  const log = await fetch("samples/testnet-2026-10-22.json").then((r) => r.json()).catch(() => null);
  paintCipher(log);
  $("count").textContent = "Static demo · the live desk runs on a Tally bulletin";
  $("st-open").textContent = "0";
  $("st-orders").textContent = String(log?.entries?.length ?? 5);
  const tbody = $("rows");
  tbody.replaceChildren(
    el("tr", {},
      el("td", {}, el("div", { class: "asset" }, el("span", { class: "glyph" }, "F0"),
        el("div", {}, el("b", {}, "Block sale f02153…ddcc"), el("small", {}, "Testnet · Oct 22 · 5 orders")))),
      el("td", { class: "r num" }, "2"),
      el("td", { class: "r num col-hide" }, "0.001 – 0.016"),
      el("td", { class: "r num col-hide" }, "0.001"),
      el("td", { class: "r num" }, "5"),
      el("td", {}, el("span", { class: "pill" }, "Settled at 0.012")),
      el("td", { class: "r" }, el("a", { class: "btn sm cta", href: "verify.html?sample=testnet-2026-10-22" }, "Clearing report"))));
}
