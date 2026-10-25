// The static site can't send frame-ancestors (a <meta> CSP ignores it), so
// refuse to render inside someone else's frame: an overlay there could
// capture the dial or swap the escrow address shown to a bidder.
if (window.top !== window.self) {
  document.documentElement.style.display = "none";
  try {
    window.top.location = window.self.location.href;
  } catch {
    /* cross-origin parent: stay hidden */
  }
}
