const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === "class" ? (n.className = v) : n.setAttribute(k, v);
  for (const c of kids) n.append(c);
  return n;
};

const list = document.getElementById("cases");
try {
  const auctions = await (await fetch("v1/auctions")).json();
  list.replaceChildren();
  document.getElementById("count").textContent = `${auctions.length} on file`;
  if (!auctions.length) list.append(el("li", { class: "case" }, el("span", { class: "dim mono" }, "No auctions on this bulletin yet.")));
  for (const a of auctions.reverse()) {
    const status = a.cleared ? "Cleared" : a.closed ? "Closed · clearing" : "Open";
    const actions = el("span", { class: "actions" });
    if (!a.closed) actions.append(el("a", { class: "btn primary", href: `bid.html?auction=${a.auction_id}` }, "Place a bid"));
    actions.append(el("a", { class: "btn", href: `verify.html?auction=${a.auction_id}` }, "Verify"));
    list.append(
      el("li", {},
        el("div", { class: "case" },
          el("span", {}, el("span", { class: "id" }, `${a.auction_id.slice(0, 8)}…${a.auction_id.slice(-4)}`)),
          el("span", { class: "meta" }, `${a.supply} item${a.supply === 1 ? "" : "s"} · ${a.levels} levels · ${a.ballots} ballot${a.ballots === 1 ? "" : "s"}`),
          el("span", { class: `chip ${a.closed ? "" : "open"}` }, status),
          actions)));
  }
} catch {
  // Static hosting (e.g. GitHub Pages): no live bulletin, but the verifier
  // runs entirely in the browser, so the recorded testnet auction still checks.
  document.getElementById("count").textContent = "static mode";
  list.replaceChildren(
    el("li", {},
      el("div", { class: "case" },
        el("span", {}, el("span", { class: "id" }, "f021530d…ddcc")),
        el("span", { class: "meta" }, "Testnet auction · Oct 22 · 5 bidders · cleared at 0.012 TAZ"),
        el("span", { class: "chip" }, "Cleared"),
        el("span", { class: "actions" }, el("a", { class: "btn primary", href: "verify.html?sample=testnet-2026-10-22" }, "Verify it yourself")))));
}
