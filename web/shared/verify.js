import { load, zec } from "./tally.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const short = (h) => `${h.slice(0, 10)}…${h.slice(-6)}`;

const q = new URLSearchParams(location.search);
const LATEST = "testnet-2026-10-22";
const qid = q.get("auction");
// With no record named, open the latest public clearing rather than an empty page.
const source = q.get("sample") || (!qid ? LATEST : null);
const first = source
  ? fetch(`samples/${encodeURIComponent(source)}.json`).catch(() => null)
  : /^[0-9a-f]{64}$/.test(qid) ? fetch(`v1/auctions/${qid}`).catch(() => null) : null;
const tally = await load(new URL("../tally_wasm.wasm", import.meta.url).href);

function verdict(ok, text, sub) {
  $("mark").className = `verdict-mark${ok === false ? " fail" : ""}`;
  $("seal").textContent = ok === false ? "✕" : ok ? "✓" : "…";
  $("verdict-text").textContent = text;
  if (sub !== undefined) $("verdict-sub").textContent = sub;
}

function render(log, source) {
  verdict(null, `Checking ${log?.entries?.length ?? 0} orders and ${log?.decryptions?.length ?? 0} decryptions…`);
  // Let the message paint before the (synchronous) WASM verification runs.
  setTimeout(() => renderNow(log, source), 30);
}

function renderNow(log, source) {
  let r;
  try {
    r = tally.verifyLog(log);
  } catch (e) {
    verdict(false, "Not a clearing record", e.message);
    return;
  }
  const s = r.summary;
  const passed = r.checks.filter((c) => c.ok).length;
  $("case-label").textContent = `${log?.manifest?.title || `Block sale ${short(s.auction_id)}`} · ${source}`;
  verdict(
    r.all_ok,
    r.all_ok ? `Verified · ${passed} of ${r.checks.length} checks pass` : `Tampering detected · ${r.checks.length - passed} check${r.checks.length - passed === 1 ? "" : "s"} fail`,
    r.all_ok
      ? "Every signature, proof, decryption and the clearing result were recomputed in this tab."
      : "This record does not match what the protocol allows. Do not rely on it.",
  );
  $("tally").textContent = `${passed} pass · ${r.checks.length - passed} fail`;

  const list = $("checks");
  list.replaceChildren();
  r.checks.forEach((c, i) => {
    const li = el("li", c.ok ? "ok" : "bad");
    li.style.animationDelay = `${i * 70}ms`;
    li.append(el("span", "st", c.ok ? "PASS" : "FAIL"));
    const body = el("span");
    body.append(el("span", "name", c.name), el("span", "detail", c.detail));
    li.append(body);
    list.append(li);
  });

  const res = s.result;
  $("kpis").hidden = false;
  $("supply").textContent = `${s.supply}`;
  $("ballots").textContent = `${s.ballots} · ${s.bonded}`;
  $("committee").textContent = `${s.threshold}`;
  const out = $("outcome");
  out.hidden = false;
  if (res && res.price_zat != null) {
    $("price").replaceChildren(zec(res.price_zat), el("small", "", " ZEC"));
    out.textContent = res.outcome[0].toUpperCase() + res.outcome.slice(1);
    out.className = "pill";
  } else {
    $("price").textContent = res ? "Void" : s.closed ? "Clearing…" : "Sealed";
    out.textContent = res ? res.outcome : s.closed ? "Closed · clearing" : "Open for orders";
    out.className = `pill ${res ? "" : "wait"}`;
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
    rung.title = opened.has(k) ? `T${k} = ${opened.get(k)} orders at ≥ ${zec(p)} ZEC` : `Level ${k}: sealed, never decrypted`;
    ladder.append(rung);
  });
  ladder.setAttribute("aria-label", `${opened.size} of ${s.ladder_zat.length} price totals were opened; the rest stayed sealed`);
  $("opened").textContent = `${opened.size} of ${s.ladder_zat.length} aggregates opened`;
  $("ladder-sec").hidden = false;

  const w = $("winners");
  w.replaceChildren();
  if (res?.winners?.length) {
    const settled = new Map(s.settlements.map((x) => [x.P, x.txid]));
    for (const p of res.winners) {
      const tr = el("tr");
      const tx = settled.get(p);
      const st = el("td");
      st.append(tx ? el("span", "mono", `tx ${short(tx)}`) : el("span", "pill wait", "Awaiting settlement"));
      tr.append(el("td", "mono", short(p)), st);
      w.append(tr);
    }
    $("winners-sec").hidden = false;
  } else {
    $("winners-sec").hidden = true;
  }
}

async function fromUrl() {
  const r = await first;
  if (source) {
    if (r?.ok) return render(await r.json(), source === LATEST ? "Oct 22 testnet clearing" : "saved record");
    return verdict(null, "Open a clearing record", "Drop a saved auction-log.json below.");
  }
  if (!r?.ok) {
    verdict(null, "Clearing report not available here", "Pick an offering from the Offerings list, or drop a saved auction-log.json below.");
    return;
  }
  render(await r.json(), "live from the desk");
}

async function fromFile(file) {
  try {
    render(JSON.parse(await file.text()), `file ${file.name}`);
  } catch {
    verdict(false, "That file isn't JSON");
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
