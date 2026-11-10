// Sign-in page. The token from the printed link (?token=...) is posted once and then removed from the
// address bar; it never travels in a GET request again. All text is set with textContent.
"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  try {
    const t = localStorage.getItem("ca.theme");
    if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  } catch (e) { /* storage unavailable */ }

  const params = new URLSearchParams(location.search);
  const linkToken = params.get("token") || "";
  if (linkToken) {
    history.replaceState(null, "", "/login");
    $("token").value = linkToken;
    $("token-row").hidden = true;
    $("token-note").hidden = false;
  }

  let consentRequired = false;
  function banner(id, c) {
    const b = $(id);
    if (!c || !c.text) { b.hidden = true; return; }
    b.textContent = c.text; b.style.background = c.background; b.style.color = c.color; b.hidden = false;
  }
  function showError(msg) { const e = $("login-error"); e.textContent = msg; e.hidden = !msg; }

  fetch("/api/public", { credentials: "same-origin" }).then((r) => r.json()).then((info) => {
    if (info.authed) { location.replace("/"); return; }
    banner("cls-top", info.classification); banner("cls-bottom", info.classification);
    if (info.consent_text) {
      consentRequired = true;
      $("consent-text").textContent = info.consent_text;
      $("consent").hidden = false;
    }
    if (linkToken && !consentRequired) $("login-form").requestSubmit();
  }).catch(() => showError("Cannot reach the dashboard server."));

  $("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    showError("");
    const token = $("token").value.trim();
    if (consentRequired && !$("consent-check").checked) { showError("Acknowledge the notice to continue."); return; }
    if (!token) { showError("Enter the access token."); $("token-row").hidden = false; $("token").focus(); return; }
    const btn = $("login-btn");
    btn.disabled = true; btn.textContent = "Signing in…";
    try {
      const r = await fetch("/api/login", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CA-Request": "1" },
        body: JSON.stringify({ token, consent: $("consent-check").checked }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || "Sign-in failed (HTTP " + r.status + ")");
      location.replace("/");
    } catch (err) {
      showError(err.message);
      $("token-row").hidden = false; $("token-note").hidden = true;
      btn.disabled = false; btn.textContent = "Sign in";
    }
  });
})();
