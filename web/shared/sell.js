import { load, zec, chainTip, blocksLeft } from "./tally.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const short = (h) => `${h.slice(0, 10)}…${h.slice(-6)}`;

const tip = chainTip();
const tally = await load(new URL("../tally_wasm.wasm", import.meta.url).href);

let committee = null;
let draft = null;
let sellerKey = null; // { auction_id, seller_sk, bulletin }: only ever saved to a file
let keySaved = false;
const endorsements = new Map(); // j -> endorsement

function status(id, text, kind = "") {
  $(id).textContent = text;
  $(id).className = `status ${kind}`;
}
const zat = (v) => Math.round(parseFloat(v) * 1e8);
const int = (v) => (/^\d+$/.test(v.trim()) ? parseInt(v, 10) : NaN);
function download(name, obj) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  URL.revokeObjectURL(url);
}
async function readJson(file) {
  return JSON.parse(await file.text());
}
function dropZone(zone, input, onFiles) {
  input.addEventListener("change", (e) => e.target.files.length && onFiles([...e.target.files]));
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("over");
    if (e.dataTransfer.files.length) onFiles([...e.dataTransfer.files]);
  });
}

// ---- chain ----
const t = await tip;
$("chain").textContent = t ? `Chain at block ${t.height.toLocaleString("en-US")}` : "";

// ---- terms + live preview ----
function terms() {
  return {
    title: $("f-title").value.trim(),
    supply: int($("f-supply").value),
    bond_zat: zat($("f-bond").value),
    step_zat: zat($("f-step").value),
    levels: int($("f-levels").value),
    close_in: int($("f-window").value),
    min_batch: int($("f-min").value),
    settle_window: int($("f-settle").value),
  };
}
function preview() {
  const f = terms();
  $("pv-name").textContent = f.title || "Untitled offering";
  $("pv-units").textContent = Number.isFinite(f.supply) ? String(f.supply) : "—";
  const ok = f.step_zat > 0 && f.levels >= 1 && f.levels <= 64;
  $("pv-range").textContent = ok ? `${zec(f.step_zat)} – ${zec(f.step_zat * f.levels)} ZEC` : "—";
  $("pv-dep").textContent = f.bond_zat > 0 ? `${zec(f.bond_zat)} ZEC` : "—";
  $("pv-close").textContent = Number.isFinite(f.close_in) ? (t ? `block ${(t.height + f.close_in).toLocaleString("en-US")} · in ${blocksLeft(f.close_in, t)}` : `${f.close_in} blocks after opening`) : "—";
  $("pv-min").textContent = Number.isFinite(f.min_batch) ? `${f.min_batch} funded orders` : "—";
  const mini = $("pv-ladder");
  mini.style.setProperty("--n", ok ? f.levels : 16);
  mini.replaceChildren(...Array.from({ length: ok ? f.levels : 16 }, () => el("i")));
  // Any change after signing makes a different offering: start over.
  if (draft) resetDraft();
}
for (const id of ["f-title", "f-supply", "f-bond", "f-step", "f-levels", "f-window", "f-min", "f-settle", "f-coll", "f-escrow", "f-forfeit"]) {
  $(id).addEventListener("input", preview);
}
preview();

// ---- mint record + committee ----
dropZone($("drop-mint"), $("file-mint"), async ([f]) => {
  try {
    const rec = await readJson(f);
    if (!/^[0-9a-f]{64}$/.test(rec.collection_id ?? "")) throw new Error();
    $("f-coll").value = rec.collection_id;
    $("mint-note").textContent = `Collection ${short(rec.collection_id)} · ${rec.items?.length ?? "?"} items`;
    preview();
  } catch {
    $("mint-note").textContent = "That file has no collection_id.";
  }
});
dropZone($("drop-comm"), $("file-comm"), async ([f]) => {
  try {
    const c = await readJson(f);
    if (!c.H || !Array.isArray(c.X) || !c.t || !c.n) throw new Error();
    committee = c;
    $("comm-note").textContent = `${c.t}-of-${c.n}: ${(c.members ?? []).join(", ")}`;
    $("pv-comm").textContent = `${c.t}-of-${c.n} threshold`;
    preview();
  } catch {
    committee = null;
    $("comm-note").textContent = "That isn't a committee.json.";
  }
});

// ---- sign ----
function resetDraft() {
  draft = null;
  sellerKey = null;
  keySaved = false;
  endorsements.clear();
  $("signed").hidden = true;
  $("end-list").replaceChildren();
  $("pub-btn").disabled = true;
  status("sign-status", "Terms changed. Sign again.", "");
}
$("sign-btn").addEventListener("click", async () => {
  const f = terms();
  const bad = Object.entries(f).find(([k, v]) => k !== "title" && !(Number.isFinite(v) && v > 0));
  if (bad) return status("sign-status", `Check the ${bad[0].replace("_", " ")} field.`, "err");
  if (f.min_batch < 5) return status("sign-status", "Minimum funded orders must be at least 5, so a small book can't be unmasked.", "err");
  if (!committee) return status("sign-status", "Drop the committee.json first.", "err");
  if (!t) return status("sign-status", "This desk doesn't know the chain height, so it can't set the order window.", "err");
  try {
    const out = tally.draftOffering({
      ...f,
      collection_id: $("f-coll").value.trim(),
      escrow_ua: $("f-escrow").value.trim(),
      forfeit_ua: $("f-forfeit").value.trim(),
      open_height: t.height,
      committee,
    });
    draft = out.draft;
    sellerKey = { ...out.seller_key, bulletin: location.origin };
  } catch (e) {
    return status("sign-status", e.message, "err");
  }
  status("sign-status", "Signed. Save your seller key before anything else.", "ok");
  const kv = $("draft-kv");
  kv.replaceChildren(
    el("span", "", "Offering ID"), el("span", "", short(draft.auction_id)),
    el("span", "", "Opens"), el("span", "", `block ${draft.open_height.toLocaleString("en-US")}`),
    el("span", "", "Closes"), el("span", "", `block ${draft.close_height.toLocaleString("en-US")}`),
  );
  $("signed").hidden = false;
});
$("key-btn").addEventListener("click", () => {
  // Same shape as `tally-settle auction-create` writes, so the CLI accepts it.
  download("tally-seller-key.json", sellerKey);
  keySaved = true;
  $("key-btn").textContent = "Seller key saved";
});
$("draft-btn").addEventListener("click", () => download("draft.json", draft));
window.addEventListener("beforeunload", (e) => {
  if (sellerKey && !keySaved) e.preventDefault();
});

// ---- endorsements + publish ----
function renderEndorsements() {
  const n = draft?.committee?.n ?? committee?.n ?? 3;
  const names = draft?.committee?.members ?? committee?.members ?? [];
  const list = $("end-list");
  list.replaceChildren();
  for (let j = 1; j <= n; j++) {
    const row = el("div", "member-row");
    row.append(el("span", "", names[j - 1] ?? `Member ${j}`), el("span", endorsements.has(j) ? "pill open" : "pill wait", endorsements.has(j) ? "Co-signed" : "Waiting"));
    list.append(row);
  }
  $("pub-btn").disabled = !draft || endorsements.size < n;
}
dropZone($("drop-end"), $("file-end"), async (files) => {
  if (!draft) return status("pub-status", "Sign the draft first.", "err");
  for (const f of files) {
    try {
      const e = await readJson(f);
      if (!Number.isInteger(e.j) || !e.sig) throw new Error();
      endorsements.set(e.j, e);
    } catch {
      status("pub-status", `${f.name} isn't an endorsement file.`, "err");
    }
  }
  renderEndorsements();
});
$("pub-btn").addEventListener("click", async () => {
  if (!keySaved) return status("pub-status", "Save your seller key first. Without it you can't close the order window.", "err");
  let manifest;
  try {
    manifest = tally.attachEndorsements(draft, [...endorsements.values()]);
  } catch (e) {
    return status("pub-status", `An endorsement doesn't check out: ${e.message}`, "err");
  }
  $("pub-btn").disabled = true;
  status("pub-status", "Publishing…");
  const r = await fetch("v1/auctions", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(manifest) }).catch(() => null);
  if (!r?.ok) {
    $("pub-btn").disabled = false;
    return status("pub-status", `The desk refused it${r ? ` (${await r.text()})` : ""}.`, "err");
  }
  const link = el("a", "", "Open the offering page");
  link.href = `bid.html?auction=${draft.auction_id}`;
  status("pub-status", "Live. Buyers can place sealed orders now. ", "ok");
  $("pub-status").append(link);
});
renderEndorsements();

// ---- close ----
let closing = null; // { key, log }
dropZone($("drop-key"), $("file-key"), async ([f]) => {
  try {
    const key = await readJson(f);
    if (!/^[0-9a-f]{64}$/.test(key.auction_id ?? "") || !key.seller_sk) throw new Error("not a seller key");
    const r = await fetch(`v1/auctions/${key.auction_id}`);
    if (!r.ok) throw new Error("this desk doesn't list that offering");
    const log = await r.json();
    closing = { key, log };
    const m = log.manifest;
    const ended = t && t.height >= m.close_height;
    $("close-kv").replaceChildren(
      el("span", "", "Offering"), el("span", "", m.title || short(m.auction_id)),
      el("span", "", "Sealed orders"), el("span", "", String(log.entries.length)),
      el("span", "", "Close height"), el("span", "", `${m.close_height.toLocaleString("en-US")}${t ? (ended ? " · reached" : ` · in ${blocksLeft(m.close_height - t.height, t)}`) : ""}`),
    );
    if (log.close) {
      $("close-btn").disabled = true;
      return status("close-status", "Already closed.", "ok");
    }
    $("close-btn").disabled = !ended;
    status("close-status", ended ? "Ready to close." : "The order window is still open. You can close once the chain reaches the close height.", ended ? "ok" : "");
  } catch (e) {
    closing = null;
    $("close-btn").disabled = true;
    status("close-status", `Couldn't use that file: ${e.message}`, "err");
  }
});
$("close-btn").addEventListener("click", async () => {
  if (!closing) return;
  // Re-read the log right before signing, so the close covers every order.
  const log = await (await fetch(`v1/auctions/${closing.key.auction_id}`)).json();
  let c;
  try {
    c = tally.signClose(closing.key.seller_sk, log);
  } catch (e) {
    return status("close-status", e.message, "err");
  }
  const r = await fetch(`v1/auctions/${closing.key.auction_id}/close`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(c) }).catch(() => null);
  if (!r?.ok) return status("close-status", "The desk refused the close.", "err");
  $("close-btn").disabled = true;
  status("close-status", `Closed with ${c.count} orders. Send the committee the offering link to clear it.`, "ok");
});
