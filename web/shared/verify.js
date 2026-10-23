import { load, zec } from "./tally.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const short = (h) => `${h.slice(0, 10)}…${h.slice(-6)}`;

const tally = await load(new URL("../tally_wasm.wasm", import.meta.url).href);

function render(log, source) {
  $("verdict-text").textContent = `Checking ${log?.entries?.length ?? 0} ballots and ${log?.decryptions?.length ?? 0} decryptions…`;
  // Let the message paint before the (synchronous) WASM verification runs.
  setTimeout(() => renderNow(log, source), 30);
}

function renderNow(log, source) {
  let r;
  try {
    r = tally.verifyLog(log);
  } catch (e) {
    $("verdict").className = "verdict fail";
    $("verdict-text").textContent = "Not an auction log";
    $("verdict-sub").textContent = e.message;
    return;
  }
  const s = r.summary;
  const passed = r.checks.filter((c) => c.ok).length;
  $("case-label").textContent = `Case ${short(s.auction_id)} · ${source}`;
  $("verdict").className = `verdict ${r.all_ok ? "pass" : "fail"}`;
  $("verdict-text").textContent = r.all_ok ? `Checks out · ${passed}/${r.checks.length}` : `Tampering detected · ${passed}/${r.checks.length}`;
  $("tally").textContent = `${passed} pass · ${r.checks.length - passed} fail`;

  const list = $("checks");
  list.replaceChildren();
  r.checks.forEach((c, i) => {
    const li = el("li", c.ok ? "ok" : "bad");
    li.style.animationDelay = `${i * 90}ms`;
    li.append(el("span", "st", c.ok ? "PASS" : "FAIL"));
    const body = el("span");
    body.append(el("span", "name", c.name), el("span", "detail", c.detail));
    li.append(body);
    list.append(li);
  });

  // The take
  const res = s.result;
  $("result-sec").hidden = false;
  $("supply").textContent = `${s.supply}`;
  $("ballots").textContent = `${s.ballots} · ${s.bonded}`;
  $("committee").textContent = `${s.threshold} · ${s.committee.length} named`;
  if (res && res.price_zat != null) {
    $("price").replaceChildren(zec(res.price_zat), Object.assign(document.createElement("small"), { textContent: " ZEC" }));
    $("outcome").textContent = res.outcome;
  } else {
    $("price").textContent = res ? "Void" : s.closed ? "Clearing…" : "Sealed";
    $("outcome").textContent = res ? res.outcome : s.closed ? "closed" : "open for bids";
  }

  // Ladder: hatched = never opened; only decrypted totals carry numbers.
  const opened = new Map(Object.entries(res?.totals ?? {}).map(([k, v]) => [Number(k), v]));
  for (const k of s.decrypted_totals) if (!opened.has(k)) opened.set(k, "·");
  const ladder = $("ladder");
  ladder.style.setProperty("--levels", s.ladder_zat.length);
  ladder.replaceChildren();
  const kstar = res?.outcome === "cleared" ? res.k_star : res?.outcome === "undersubscribed" ? 1 : 0;
  s.ladder_zat.forEach((p, i) => {
    const k = i + 1;
    const rung = el("div", `rung${opened.has(k) ? " opened" : ""}${k === kstar ? " cleared" : ""}`);
    rung.append(el("div", "cell", opened.has(k) ? String(opened.get(k)) : ""), el("div", "p", zec(p)));
    rung.title = opened.has(k) ? `T${k} = ${opened.get(k)} ballots at ≥ ${zec(p)} ZEC` : `Level ${k}: sealed, never decrypted`;
    ladder.append(rung);
  });
  ladder.setAttribute("aria-label", `${opened.size} of ${s.ladder_zat.length} price totals were opened; the rest stayed sealed`);
  $("opened").textContent = `${opened.size} of ${s.ladder_zat.length} opened · ${s.cells_opened} ballot cells`;
  $("ladder-sec").hidden = false;

  // Winners + settlements
  const w = $("winners");
  w.replaceChildren();
  if (res?.winners?.length) {
    const settled = new Map(s.settlements.map((x) => [x.P, x.txid]));
    for (const p of res.winners) {
      const li = el("li");
      li.append(el("span", "hash", short(p)));
      const tx = settled.get(p);
      li.append(tx ? el("span", "mono dim", `settled · tx ${short(tx)}`) : el("span", "chip open", "awaiting settlement"));
      w.append(li);
    }
    $("winners-sec").hidden = false;
  } else {
    $("winners-sec").hidden = true;
  }
}

async function fromUrl() {
  const q = new URLSearchParams(location.search);
  if (q.get("sample")) {
    const r = await fetch(`samples/${encodeURIComponent(q.get("sample"))}.json`);
    if (r.ok) return render(await r.json(), "saved sample");
  }
  const id = q.get("auction");
  if (!id || !/^[0-9a-f]{64}$/.test(id)) {
    $("verdict-text").textContent = "Pick a case or drop a log";
    return;
  }
  const r = await fetch(`v1/auctions/${id}`);
  if (!r.ok) {
    $("verdict-text").textContent = "No such auction on this bulletin";
    return;
  }
  render(await r.json(), "live from the bulletin");
}

async function fromFile(file) {
  try {
    render(JSON.parse(await file.text()), `file ${file.name}`);
  } catch {
    $("verdict").className = "verdict fail";
    $("verdict-text").textContent = "That file isn't JSON";
  }
}

$("file").addEventListener("change", (e) => e.target.files[0] && fromFile(e.target.files[0]));
const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  if (e.dataTransfer.files[0]) fromFile(e.dataTransfer.files[0]);
});

fromUrl();
