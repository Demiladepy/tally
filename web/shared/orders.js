import { zec } from "./tally.js";

const $ = (id) => document.getElementById(id);
const short = (h) => `${h.slice(0, 8)}…${h.slice(-6)}`;
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

// Keys live only in this array, in memory. Nothing is stored or uploaded;
// the only requests are reads of public offering logs.
const keys = [];

function statusOf(key, log) {
  if (!log) return ["Desk unreachable", "bad"];
  const i = key.receipt?.i;
  const entry = log.entries.find((e) => e.i === i);
  if (!entry || entry.ballot.P !== key.P) return ["Not on this book", "bad"];
  const res = log.result;
  if (!log.close) return ["Sealed · order window open", "open"];
  if (log.bonds && !log.bonds.bonded.includes(i)) return ["Not funded · excluded", "bad"];
  if (!res) return ["Funded · awaiting clearing", "wait"];
  if (res.outcome === "void") return ["Void · deposit refunded", ""];
  if (!res.winners.includes(key.P)) return ["Not allocated · deposit refunded", ""];
  if (log.settlements.some((s) => s.P === key.P)) return ["Allocated · settled", "open"];
  return ["Allocated · settle now", "wait"];
}

async function render() {
  const tbody = $("rows");
  tbody.replaceChildren();
  if (!keys.length) {
    const tr = el("tr");
    const td = el("td", "empty", "No order keys opened yet.");
    td.colSpan = 6;
    tr.append(td);
    return tbody.append(tr);
  }
  for (const key of keys) {
    const log = await fetch(`v1/auctions/${key.auction_id}`).then((r) => (r.ok ? r.json() : null)).catch(() => null);
    const [text, kind] = statusOf(key, log);
    const res = log?.result;
    const settled = log?.settlements?.find((s) => s.P === key.P);
    const tr = el("tr");
    const name = el("div");
    name.append(el("b", "", `Block sale ${short(key.auction_id)}`), el("small", "", `order #${key.receipt?.i ?? "?"}`));
    const asset = el("div", "asset");
    asset.append(el("span", "glyph", key.auction_id.slice(0, 2).toUpperCase()), name);
    const off = el("td");
    off.append(asset);
    const pill = el("td");
    pill.append(el("span", `pill ${kind}`, text));
    const act = el("td", "r");
    const a = el("a", "btn sm", "Clearing report");
    a.href = `verify.html?auction=${key.auction_id}`;
    act.append(a);
    tr.append(
      off,
      el("td", "mono", short(key.P)),
      pill,
      el("td", "r num col-hide", res?.price_zat != null ? `${zec(res.price_zat)} ZEC` : "—"),
      el("td", "r mono col-hide", settled ? short(settled.txid) : "—"),
      act,
    );
    tbody.append(tr);
  }
}

async function open(files) {
  for (const f of files) {
    try {
      const k = JSON.parse(await f.text());
      if (!/^[0-9a-f]{64}$/.test(k.auction_id) || typeof k.P !== "string") continue;
      if (!keys.some((x) => x.P === k.P)) keys.push(k);
    } catch {
      /* not a key file */
    }
  }
  render();
}

$("file").addEventListener("change", (e) => open(e.target.files));
const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  open(e.dataTransfer.files);
});
