const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === "class" ? (n.className = v) : n.setAttribute(k, v);
  for (const c of kids) n.append(c);
  return n;
};

const list = document.getElementById("cases");
try {
  const auctions = await (await fetch("/v1/auctions")).json();
  list.replaceChildren();
  document.getElementById("count").textContent = `${auctions.length} on file`;
  if (!auctions.length) list.append(el("li", { class: "case" }, el("span", { class: "dim mono" }, "No auctions on this bulletin yet.")));
  for (const a of auctions.reverse()) {
    const status = a.cleared ? "Cleared" : a.closed ? "Closed · clearing" : "Open";
    const actions = el("span", { class: "actions" });
    if (!a.closed) actions.append(el("a", { class: "btn primary", href: `/bid.html?auction=${a.auction_id}` }, "Place a bid"));
    actions.append(el("a", { class: "btn", href: `/verify.html?auction=${a.auction_id}` }, "Verify"));
    list.append(
      el("li", {},
        el("div", { class: "case" },
          el("span", {}, el("span", { class: "id" }, `${a.auction_id.slice(0, 8)}…${a.auction_id.slice(-4)}`)),
          el("span", { class: "meta" }, `${a.supply} item${a.supply === 1 ? "" : "s"} · ${a.levels} levels · ${a.ballots} ballot${a.ballots === 1 ? "" : "s"}`),
          el("span", { class: `chip ${a.closed ? "" : "open"}` }, status),
          actions)));
  }
} catch {
  list.replaceChildren(el("li", { class: "case" }, el("span", { class: "dim mono" }, "Bulletin unreachable. You can still verify a saved log file on the Verify page.")));
}
