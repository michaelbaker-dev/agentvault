"use strict";
// Keys web interface. Builds every element with the DOM API (never innerHTML),
// so names, notes and descriptions can't inject markup.
(() => {
  const S = {
    status: null,
    csrf: null,
    view: "secrets",
    secrets: [],
    filter: "",
    range: "24h",
    timer: null,
    pollTimer: null,
    observers: [],
  };
  const VIEWS = { secrets: "Secrets", rotation: "Rotation", import: "Import", dashboard: "Dashboard", tokens: "Tokens", settings: "Settings" };
  const SCOPES = [
    ["list", "List", "See names and descriptions (never values)."],
    ["proxy", "Proxy", "Call a provider through the vault without seeing the key."],
    ["read", "Read", "Fetch raw values."],
    ["write", "Write", "Add keys to this vault and change their values, notes and tags. (To let it make changes at a provider, such as GitHub, untick \"GET requests only\" instead.)"],
    ["delete", "Delete", "Delete secrets."],
  ];

  // ---------------------------------------------------------------- DOM helpers

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k === "value") el.value = v;
      else if (k === "checked") el.checked = !!v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    add(el, kids);
    return el;
  }
  function add(el, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false) continue;
      el.append(k instanceof Node ? k : document.createTextNode(String(k)));
    }
  }
  function fill(el, ...kids) {
    el.replaceChildren();
    add(el, kids);
  }
  const SVGNS = "http://www.w3.org/2000/svg";
  function s(tag, attrs, ...kids) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, String(v));
    add(el, kids);
    return el;
  }
  function safeUrl(u) {
    try {
      const x = new URL(u);
      return x.protocol === "https:" ? x.href : null;
    } catch (_) {
      return null;
    }
  }

  // ---------------------------------------------------------------- formatting

  const num = (n) => Number(n || 0).toLocaleString();
  function fmtMs(x) {
    if (!x) return "0 ms";
    if (x < 10) return x.toFixed(2) + " ms";
    if (x < 100) return x.toFixed(1) + " ms";
    if (x < 10000) return Math.round(x).toLocaleString() + " ms";
    return (x / 1000).toFixed(1) + " s";
  }
  function ago(ms) {
    if (!ms) return "never";
    const d = (Date.now() - ms) / 1000;
    if (d < 45) return "just now";
    if (d < 3600) return Math.round(d / 60) + "m ago";
    if (d < 86400) return Math.round(d / 3600) + "h ago";
    if (d < 86400 * 14) return Math.round(d / 86400) + "d ago";
    return new Date(ms).toLocaleDateString();
  }
  const when = (ms) => (ms ? new Date(ms).toLocaleString() : "");
  function fmtBucket(t, bucketMs) {
    const d = new Date(t);
    if (bucketMs < 86400000) return d.toLocaleTimeString([], { hour: "numeric" }) + (bucketMs > 3600000 ? " " + d.toLocaleDateString([], { month: "short", day: "numeric" }) : "");
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  }
  const plural = (n, w) => `${num(n)} ${w}${n === 1 ? "" : "s"}`;

  // ---------------------------------------------------------------- API

  async function api(method, path, body, retried) {
    const opt = { method, headers: {}, credentials: "same-origin", cache: "no-store" };
    if (S.csrf) opt.headers["x-agentvault-csrf"] = S.csrf;
    if (body !== undefined) {
      opt.headers["content-type"] = "application/json";
      opt.body = JSON.stringify(body);
    }
    const r = await fetch(path, opt);
    let data = null;
    try {
      data = await r.json();
    } catch (_) {}
    if (r.status === 428 && !retried) {
      // Revealing values, creating tokens, deleting and proxy changes need a
      // recent passphrase; ask for it, then retry once.
      await confirmPassphrase();
      return api(method, path, body, true);
    }
    if (!r.ok) {
      const err = new Error((data && data.error) || `Request failed (HTTP ${r.status})`);
      err.status = r.status;
      if (r.status === 401 && S.csrf && !path.startsWith("/v1/session")) {
        S.csrf = null;
        toast("Your session ended. Sign in again.", true);
        boot();
      }
      throw err;
    }
    return data;
  }

  function toast(msg, isErr) {
    const t = h("div", { class: "toast" + (isErr ? " err" : ""), role: isErr ? "alert" : "status", text: msg });
    document.getElementById("toasts").append(t);
    setTimeout(() => t.remove(), isErr ? 6000 : 3500);
  }

  // ---------------------------------------------------------------- boot & auth

  function render(node) {
    clearTimers();
    document.getElementById("app").replaceChildren(node);
  }
  function clearTimers() {
    clearInterval(S.timer);
    clearTimeout(S.pollTimer);
    S.observers.forEach((o) => o.disconnect());
    S.observers = [];
  }

  async function boot() {
    try {
      S.status = await api("GET", "/v1/status");
      const sess = await api("GET", "/v1/session");
      S.csrf = sess.signed_in ? sess.csrf : null;
    } catch (e) {
      render(h("div", { class: "auth" }, h("div", { class: "card" }, h("h1", { text: "Can't reach the vault" }), h("p", { text: e.message }))));
      return;
    }
    if (!S.status.initialized) return render(setupScreen());
    if (!S.csrf) return render(loginScreen());
    routeFromHash();
    render(shell());
  }

  function authCard(title, intro, form) {
    return h(
      "div",
      { class: "auth" },
      h("div", { class: "card" }, h("img", { src: "/favicon.svg", alt: "", width: 36, height: 36 }), h("h1", { text: title }), h("p", {}, intro), form),
    );
  }

  function notOwner() {
    const c = S.status.caller;
    return authCard("Not allowed from this device", `This device (${c.node}, signed in to Tailscale as ${c.user}) isn't one of the vault owner's devices. Open this page from one of the owner's own machines.`, null);
  }

  function setupScreen() {
    if (!S.status.owner_device) return notOwner();
    const p1 = h("input", { class: "input", type: "password", autocomplete: "new-password", required: true, minlength: 12, id: "p1" });
    const p2 = h("input", { class: "input", type: "password", autocomplete: "new-password", required: true, minlength: 12, id: "p2" });
    const err = h("p", { class: "form-error", role: "alert" });
    const btn = h("button", { class: "btn primary", type: "submit", text: "Create vault" });
    const form = h(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          if (p1.value !== p2.value) return (err.textContent = "The passphrases don't match.");
          btn.disabled = true;
          btn.textContent = "Creating…";
          try {
            const r = await api("POST", "/v1/setup", { passphrase: p1.value });
            S.csrf = r.csrf;
            boot();
          } catch (ex) {
            err.textContent = ex.message;
            btn.disabled = false;
            btn.textContent = "Create vault";
          }
        },
      },
      h("div", { class: "field" }, h("label", { for: "p1", text: "Passphrase" }), p1, h("span", { class: "hint", text: "At least 12 characters. A few random words works well." })),
      h("div", { class: "field" }, h("label", { for: "p2", text: "Type it again" }), p2),
      err,
      btn,
    );
    return authCard(
      "Set up your vault",
      "Choose the passphrase that encrypts everything. It's never stored. If you lose it, the secrets can't be recovered, so keep a copy somewhere offline.",
      form,
    );
  }

  function loginScreen() {
    if (!S.status.owner_device) return notOwner();
    const p = h("input", { class: "input", type: "password", autocomplete: "current-password", required: true, id: "pw" });
    const err = h("p", { class: "form-error", role: "alert" });
    const btn = h("button", { class: "btn primary", type: "submit", text: S.status.sealed ? "Unlock and sign in" : "Sign in" });
    const form = h(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          btn.disabled = true;
          try {
            const r = await api("POST", "/v1/session", { passphrase: p.value });
            S.csrf = r.csrf;
            boot();
          } catch (ex) {
            err.textContent = ex.message;
            btn.disabled = false;
            p.select();
          }
        },
      },
      h("div", { class: "field" }, h("label", { for: "pw", text: "Passphrase" }), p),
      err,
      btn,
    );
    setTimeout(() => p.focus());
    return authCard(
      S.status.sealed ? "Vault is locked" : "Sign in",
      S.status.sealed
        ? "Nothing can be decrypted until you unlock it. Apps and tokens start working again as soon as you do."
        : `Signed in to Tailscale on ${S.status.caller.node} as ${S.status.caller.user}.`,
      form,
    );
  }

  // ---------------------------------------------------------------- shell

  function shell() {
    const tabs = Object.entries(VIEWS).map(([k, label]) => h("a", { class: "tab", href: "#/" + k, "data-view": k, text: label }));
    const header = h(
      "header",
      { class: "top" },
      h("div", { class: "brand" }, h("img", { src: "/favicon.svg", alt: "", width: 22, height: 22 }), "AgentVault"),
      h("nav", { class: "tabs", "aria-label": "Sections" }, tabs),
      h(
        "div",
        { class: "who" },
        h("span", { class: "chip", title: S.status.caller.user, text: S.status.caller.node }),
        h("button", { class: "btn ghost", onclick: lockVault, title: "Wipe the key from memory; apps stop working until you unlock", text: "Lock" }),
        h("button", { class: "btn ghost", onclick: signOut, text: "Sign out" }),
      ),
    );
    const main = h("main", { id: "main" });
    setTimeout(renderView);
    return h("div", {}, header, main);
  }

  function renderView() {
    clearTimers();
    const main = document.getElementById("main");
    if (!main) return;
    document.querySelectorAll(".tab").forEach((t) => {
      if (t.dataset.view === S.view) t.setAttribute("aria-current", "page");
      else t.removeAttribute("aria-current");
    });
    const fn = { secrets: secretsView, rotation: rotationView, import: importView, dashboard: dashboardView, tokens: tokensView, settings: settingsView, approve: approveView }[S.view];
    main.replaceChildren(fn());
    window.scrollTo(0, 0);
  }

  window.addEventListener("hashchange", () => {
    if (!S.csrf) return;
    if (routeFromHash()) renderView();
  });

  // `#/approve/<id>` opens the station approval page (not in the menu: a
  // station's Control Deck links to it); everything else is a menu view.
  function routeFromHash() {
    const v = location.hash.replace(/^#\/?/, "");
    const m = v.match(/^approve(?:\/([0-9a-f]{32}))?/);
    if (m) {
      S.view = "approve";
      S.approveId = m[1] || null;
      return true;
    }
    if (!VIEWS[v]) {
      if (!S.view) S.view = "secrets";
      return false;
    }
    S.view = v;
    return true;
  }

  async function lockVault() {
    if (!confirm("Lock the vault? The key is wiped from memory and every app and token stops working until you sign in again.")) return;
    try {
      await api("POST", "/v1/seal");
    } catch (_) {}
    S.csrf = null;
    boot();
  }

  async function signOut() {
    try {
      await api("DELETE", "/v1/session");
    } catch (_) {}
    S.csrf = null;
    boot();
  }

  const head = (title, sub) => h("div", { class: "head" }, h("h1", { text: title }), sub ? h("p", { class: "sub", text: sub }) : null);
  const errBox = (e) => h("div", { class: "note error-box", role: "alert", text: e.message || String(e) });

  // ---------------------------------------------------------------- dialogs

  function openDialog(title, fields, submitLabel, onSubmit, danger) {
    const err = h("p", { class: "form-error", role: "alert" });
    const submit = h("button", { class: "btn " + (danger ? "danger" : "primary"), type: "submit", text: submitLabel });
    const dlg = h("dialog", {});
    const close = () => {
      dlg.close();
      dlg.remove();
    };
    const form = h(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          submit.disabled = true;
          try {
            await onSubmit();
            close();
          } catch (ex) {
            err.textContent = ex.message;
          } finally {
            submit.disabled = false;
          }
        },
      },
      h("h2", { text: title }),
      fields,
      err,
      h("div", { class: "buttons" }, h("button", { class: "btn", type: "button", onclick: close, text: "Cancel" }), submit),
    );
    dlg.append(form);
    dlg.addEventListener("cancel", () => setTimeout(() => dlg.remove()));
    document.body.append(dlg);
    dlg.showModal();
    const first = dlg.querySelector("input, textarea");
    if (first) first.focus();
    return dlg;
  }

  let confirming = null;
  function confirmPassphrase() {
    if (confirming) return confirming;
    confirming = new Promise((resolve, reject) => {
      const pw = h("input", { class: "input", type: "password", autocomplete: "current-password", required: true });
      const err = h("p", { class: "form-error", role: "alert" });
      const dlg = h("dialog", {});
      let done = false;
      const finish = (ok) => {
        done = true;
        dlg.close();
        dlg.remove();
        confirming = null;
        ok ? resolve() : reject(new Error("Cancelled: your passphrase is needed for that."));
      };
      dlg.append(
        h(
          "form",
          {
            onsubmit: async (e) => {
              e.preventDefault();
              err.textContent = "";
              try {
                await api("POST", "/v1/session/confirm", { passphrase: pw.value });
                finish(true);
              } catch (ex) {
                err.textContent = ex.message;
                pw.select();
              }
            },
          },
          h("h2", { text: "Confirm your passphrase" }),
          h("p", { class: "small", text: "Revealing values, creating tokens, deleting secrets and changing proxy targets need your passphrase every few minutes, so a stolen browser cookie can't be used to take your keys." }),
          h("div", { class: "field" }, pw),
          err,
          h("div", { class: "buttons" }, h("button", { class: "btn", type: "button", onclick: () => finish(false), text: "Cancel" }), h("button", { class: "btn primary", type: "submit", text: "Confirm" })),
        ),
      );
      dlg.addEventListener("close", () => {
        if (!done) finish(false);
      });
      document.body.append(dlg);
      dlg.showModal();
      pw.focus();
    });
    return confirming;
  }

  function field(id, label, input, hint) {
    input.id = id;
    return h("div", { class: "field" }, h("label", { for: id, text: label }), input, hint ? h("span", { class: "hint", text: hint }) : null);
  }

  // ---------------------------------------------------------------- secrets

  const RISK = {
    high: ["crit", "High risk"],
    medium: ["warn", "Medium risk"],
    low: ["good", "Low risk"],
  };
  function riskBadge(r, reason) {
    const [cls, label] = RISK[r] || ["info", "Risk unknown"];
    return h("span", { class: "badge " + cls, title: reason || "" }, h("span", { class: "dot", "aria-hidden": "true" }), label);
  }
  function verifyBadge(v) {
    if (!v) return null;
    const map = {
      valid: ["good", "Verified with provider"],
      rejected: ["crit", "Rejected by provider"],
      restricted: ["good", "Valid, limited permissions"],
      unreachable: ["warn", "Couldn't reach provider"],
      error: ["warn", `Provider error (HTTP ${v.http_status})`],
    };
    const [cls, label] = map[v.status] || ["warn", "Not verified"];
    return h("span", { class: "badge " + cls, title: (v.reason ? v.reason + " · " : "") + (v.checked_at ? "Checked " + when(v.checked_at) : "") }, h("span", { class: "dot", "aria-hidden": "true" }), label);
  }

  function factItems(m) {
    const out = [];
    for (const [k, v] of Object.entries(m.fields || {})) out.push([k.replace(/_/g, " "), String(v)]);
    if ((m.parts || []).length) out.push(["secret parts", m.parts.join(", ")]);
    if (m.parent) out.push(["manager", m.parent]);
    if ((m.duplicates || []).length) out.push(["same value as", m.duplicates.join(", ")]);
    const f = m.facts || {};
    if (Array.isArray(f.missing) && f.missing.length) out.push(["missing", f.missing.join(", ")]);
    const v = f.verification;
    if (v && v.account) for (const [k, val] of Object.entries(v.account)) out.push([k.replace(/_/g, " "), String(val)]);
    if (v && Array.isArray(v.scopes) && v.scopes.length) out.push(["scopes", v.scopes.join(", ")]);
    if (v && v.reason) out.push(["provider said", v.reason]);
    if (f.jwt_claims) {
      for (const [k, val] of Object.entries(f.jwt_claims)) {
        out.push([k, k === "exp" || k === "iat" ? new Date(val * 1000).toLocaleString() : typeof val === "string" ? val : JSON.stringify(val)]);
      }
    }
    if (f.length) out.push(["length", plural(f.length, "character")]);
    return out;
  }

  const KIND = { password: "Password", private_key: "Private key", other: "Other" };

  function dueText(ts) {
    if (!ts) return "";
    const d = Math.round((ts - Date.now()) / 86400000);
    return d < 0 ? `overdue by ${-d} day${d === -1 ? "" : "s"}` : d === 0 ? "due today" : `due in ${d} day${d === 1 ? "" : "s"}`;
  }

  function rotationLine(m) {
    const r = m.rotation || {};
    const bits = [];
    if (r.mode === "auto") bits.push(r.ready ? "Rotates automatically" : (r.missing || []).length ? "Can rotate automatically once its details are added" : r.manager_problem ? "Can't rotate automatically: " + r.manager_problem : "Can rotate automatically once a manager is set");
    else if (r.mode === "minted") bits.push("Renews itself (short-lived tokens are made from it)");
    else if (r.mode === "never") bits.push("Can't be rotated");
    else bits.push("Rotate by hand");
    if (r.every_days && (r.mode === "auto" || r.mode === "guided")) bits.push(`every ${r.every_days} days, ${dueText(r.next_due)}`);
    if (m.rotated_at) bits.push("last rotated " + ago(m.rotated_at));
    return bits.join(" · ");
  }

  // OK hides a key's current warnings until something about it changes;
  // Restore brings them back. Same calls as the Needs attention panel.
  async function attentionAction(name, ok) {
    try {
      await api("POST", ok ? "/v1/attention/dismiss" : "/v1/attention/restore", { secret: name });
      toast(ok ? `OK'd ${name}. It comes back if anything about it changes.` : `Restored the warnings for ${name}.`);
      await loadSecrets();
      if (S.attnBox) loadAttention(S.attnBox);
    } catch (e) {
      toast(e.message, true);
    }
  }

  function attentionLine(m) {
    const a = S.attention || { items: [], dismissed: [] };
    const open = a.items.filter((i) => i.secret === m.name);
    const okd = (a.dismissed || []).filter((i) => i.secret === m.name);
    if (open.length) {
      const level = open.some((i) => i.level === "critical") ? "crit" : open.some((i) => i.level === "warning") ? "warn" : "info";
      return h(
        "div",
        { class: "card-attn " + level },
        h("span", { class: "status " + level }, h("span", { class: "dot", "aria-hidden": "true" })),
        h("span", { class: "att-reason", text: open.map((i) => i.reason).join(" · ") }),
        h("button", { class: "btn", title: "Accept this for now; it comes back if anything about the key changes", onclick: () => attentionAction(m.name, true), text: "OK" }),
      );
    }
    if (okd.length) {
      return h(
        "div",
        { class: "card-attn okd" },
        h("span", { class: "att-reason", text: "OK'd: " + okd.map((i) => i.reason).join(" · ") }),
        h("button", { class: "btn ghost", onclick: () => attentionAction(m.name, false), text: "Restore" }),
      );
    }
    return null;
  }

  function secretCard(m) {
    const pending = m.describe_status === "pending";
    const okdExposed = ((S.attention && S.attention.dismissed) || []).some((i) => i.secret === m.name && i.kind === "exposed");
    const valueBox = h("div", { class: "value", hidden: true });
    const docs = safeUrl(m.docs_url);
    const rotate = safeUrl(m.rotate_url);
    const facts = factItems(m);
    const status = m.describe_status && m.describe_status.startsWith("template") ? m.describe_status.replace(/^template \((.*)\)$/, "Built-in description: $1") : null;
    return h(
      "article",
      { class: "card" },
      h(
        "div",
        { class: "card-top" },
        h("h2", { class: "name", text: m.name }),
        m.provider_name ? h("span", { class: "chip", text: m.provider_name }) : null,
        pending ? null : riskBadge(m.risk, m.risk_reason),
        verifyBadge(m.facts && m.facts.verification),
        KIND[m.kind] ? h("span", { class: "chip", text: KIND[m.kind] }) : null,
        m.owner_only ? h("span", { class: "chip lock", title: "No token can see or use this, whatever its scopes", text: "Only you" }) : null,
        m.exposed ? h("span", { class: "badge " + (okdExposed ? "info" : "crit"), title: m.exposed }, h("span", { class: "dot", "aria-hidden": "true" }), okdExposed ? "Exposed (OK'd)" : "Exposed") : null,
        m.expires_at ? h("span", { class: "badge " + (m.expires_at < Date.now() ? "crit" : m.expires_at - Date.now() < 30 * 86400000 ? "warn" : "info"), title: when(m.expires_at) }, h("span", { class: "dot", "aria-hidden": "true" }), m.expires_at < Date.now() ? "Expired" : "Expires " + new Date(m.expires_at).toLocaleDateString()) : null,
        (m.tags || []).map((t) => h("span", { class: "tag", text: t })),
      ),
      h("p", { class: "desc" + (pending ? " pending" : ""), text: pending ? "Working out what this is…" : m.description || "No description yet." }),
      !pending && m.risk_reason ? h("p", { class: "meta", text: "Why this risk level: " + m.risk_reason }) : null,
      attentionLine(m),
      m.notes ? h("p", { class: "notes" }, h("span", { class: "label", text: "Your notes: " }), m.notes) : null,
      facts.length ? h("dl", { class: "facts" }, facts.map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", { text: v })))) : null,
      h(
        "p",
        { class: "meta" },
        rotationLine(m),
        h("br"),
        `Used ${plural(m.use_count, "time")}, last ${ago(m.last_used_at)} · version ${m.version} · updated ${ago(m.updated_at)} · `,
        m.proxy_ready ? "proxy ready" : "no proxy target",
        status ? " · " + status : null,
      ),
      valueBox,
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn", onclick: (e) => reveal(m.name, valueBox, e.currentTarget), text: "Reveal" }),
        h("button", { class: "btn", onclick: () => copyValue(m.name), text: "Copy" }),
        h("button", { class: "btn", onclick: () => secretDialog(m), text: "Edit" }),
        m.rotation && m.rotation.mode !== "never" ? h("button", { class: "btn", onclick: () => rotateDialog(m, loadSecrets), text: "Rotate" }) : null,
        h("button", { class: "btn", onclick: () => redescribe(m.name), text: "Re-describe" }),
        h("button", { class: "btn danger", onclick: () => deleteDialog(m), text: "Delete" }),
        h("span", { class: "spacer" }),
        docs ? h("a", { href: docs, target: "_blank", rel: "noopener noreferrer", text: "API docs" }) : null,
        rotate ? h("a", { href: rotate, target: "_blank", rel: "noopener noreferrer", text: "Rotate or revoke" }) : null,
      ),
    );
  }

  async function fetchValue(name) {
    const r = await api("GET", `/v1/secrets/${encodeURIComponent(name)}/value`);
    return r.value;
  }

  async function reveal(name, box, btn) {
    if (!box.hidden) {
      box.hidden = true;
      box.replaceChildren();
      btn.textContent = "Reveal";
      return;
    }
    try {
      const v = await fetchValue(name);
      box.replaceChildren(h("code", { text: v }), h("span", { class: "hint", text: "hides in 30s" }));
      box.hidden = false;
      btn.textContent = "Hide";
      setTimeout(() => {
        box.hidden = true;
        box.replaceChildren();
        btn.textContent = "Reveal";
      }, 30000);
    } catch (e) {
      toast(e.message, true);
    }
  }

  // Secrets copied from the vault don't stay on the clipboard (where clipboard
  // managers and sync can keep them): it's cleared after a short while unless
  // something else was copied from this page since.
  const CLIPBOARD_SECONDS = 45;
  let clipboardTimer = null;
  async function copySecret(text) {
    await navigator.clipboard.writeText(text);
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), CLIPBOARD_SECONDS * 1000);
  }

  async function copyValue(name) {
    try {
      await copySecret(await fetchValue(name));
      toast(`Copied ${name}. It's cleared from the clipboard in ${CLIPBOARD_SECONDS} seconds.`);
    } catch (e) {
      toast(e.message || "Couldn't copy", true);
    }
  }

  async function redescribe(name) {
    try {
      await api("POST", `/v1/secrets/${encodeURIComponent(name)}/describe`);
      toast(`Re-describing ${name}…`);
      await loadSecrets();
    } catch (e) {
      toast(e.message, true);
    }
  }

  const AUTO_UNLOCK_CMD = "sudo /usr/local/lib/agentvault/auto-unlock";
  // Shown when the vault won't unlock itself after the next restart.
  function autoUnlockNote() {
    const a = S.status.auto_unlock;
    const why =
      a === "failed" ? "Automatic unlock failed when the vault started: the stored passphrase is wrong." : a === "stale" ? "You changed your passphrase, so automatic unlock still has the old one." : null;
    if (!why) return null;
    return h("div", { class: "note warn", role: "status" }, why + " After the next restart the vault will stay locked until you sign in. To fix it, run this on the vault machine and enter your current passphrase: ", h("code", { text: AUTO_UNLOCK_CMD }));
  }

  function secretsView() {
    const list = h("div", { class: "cards", "aria-live": "polite" }, h("p", { class: "muted", text: "Loading…" }));
    const search = h("input", {
      type: "search",
      class: "input",
      placeholder: "Search names and descriptions",
      "aria-label": "Search secrets",
      value: S.filter,
      oninput: (e) => {
        S.filter = e.target.value;
        drawSecrets();
      },
    });
    const d = S.status.describer;
    const banner =
      d.claude_state === "missing"
        ? h("div", { class: "note" }, "Descriptions are using built-in templates. Add your Anthropic API key as ", h("code", { text: d.claude_secret }), " and Claude will write them from each key's metadata. It never sees the values.")
        : d.claude_state === "unrecognised"
          ? h("div", { class: "note" }, "Descriptions are using built-in templates: ", d.claude_problem, ".")
          : null;
    S.listEl = list;
    const unlockNote = autoUnlockNote();
    const attn = h("div", {});
    S.attnBox = attn;
    // The attention panel needs the list loaded to offer Rotate and Edit.
    loadSecrets()
      .catch((e) => list.replaceChildren(errBox(e)))
      .finally(() => loadAttention(attn));
    return h(
      "section",
      {},
      head("Secrets", "Encrypted at rest. A value is decrypted only when you, or a token with the read scope, asks for it."),
      unlockNote,
      banner,
      attn,
      h(
        "div",
        { class: "toolbar" },
        search,
        h("a", { class: "btn", href: "#/import", text: "Import a file" }),
        h("button", { class: "btn primary", onclick: () => secretDialog(null), text: "Add secret" }),
      ),
      list,
    );
  }

  const LEVEL = { critical: "crit", warning: "warn", info: "info" };

  async function loadAttention(box) {
    try {
      const r = await api("GET", "/v1/attention");
      if (!box.isConnected && box.parentNode) return;
      // The cards show their own warnings (with OK) from the same list.
      S.attention = r;
      drawSecrets();
      const byName = (n) => S.secrets.find((x) => x.name === n);
      // One line per secret, with every reason and its most urgent level.
      const rank = { critical: 0, warning: 1, info: 2 };
      const group = (items) => {
        const out = [];
        for (const it of items) {
          const g = out.find((x) => x.secret === it.secret);
          if (!g) out.push({ ...it, reasons: [it.reason] });
          else {
            g.reasons.push(it.reason);
            if (rank[it.level] < rank[g.level]) Object.assign(g, { level: it.level, action: it.action });
            else if (g.action !== "rotate" && it.action === "rotate") g.action = "rotate";
          }
        }
        return out.sort((a, b) => rank[a.level] - rank[b.level]);
      };
      const grouped = group(r.items);
      const okd = group(r.dismissed || []);
      if (!grouped.length && !okd.length) return box.replaceChildren();
      const refresh = () => {
        loadSecrets().catch(() => {});
        loadAttention(box);
      };
      const action = (it) => {
        const m = byName(it.secret);
        if (!m) return null;
        if (it.action === "rotate" && m.rotation && m.rotation.mode !== "never") return h("button", { class: "btn", type: "button", text: "Rotate", onclick: () => rotateDialog(m, refresh) });
        if (it.action === "edit") return h("button", { class: "btn", type: "button", text: "Edit", onclick: () => secretDialog(m) });
        if (it.action === "done") return h("a", { class: "btn", href: "#/rotation", text: "Open" });
        return null;
      };
      const ok = (it) =>
        h("button", {
          class: "btn",
          type: "button",
          text: "OK",
          title: "Hide this until something changes: a new value, a new expiry date, another failed check or rotation.",
          onclick: async () => {
            try {
              await api("POST", "/v1/attention/dismiss", { secret: it.secret });
              toast(`OK'd ${it.secret}. It comes back if anything about it changes.`);
              refresh();
            } catch (e) {
              toast(e.message, true);
            }
          },
        });
      const restore = (it) =>
        h("button", {
          class: "btn",
          type: "button",
          text: "Restore",
          onclick: async () => {
            try {
              await api("POST", "/v1/attention/restore", { secret: it.secret });
              refresh();
            } catch (e) {
              toast(e.message, true);
            }
          },
        });
      const line = (it, buttons, muted) =>
        h(
          "li",
          { class: muted ? "okd" : null },
          h("span", { class: "status " + (muted ? "info" : LEVEL[it.level] || "info") }, h("span", { class: "dot", "aria-hidden": "true" })),
          h("span", { class: "mono", text: it.secret }),
          h("span", { class: "att-reason", text: it.reasons.join(" · ") }),
          h("span", { class: "row-actions" }, buttons),
        );
      const okdList = h("ul", { class: "att-list okd-list", hidden: true }, okd.map((it) => line(it, [restore(it)], true)));
      const okdToggle = okd.length
        ? h("p", { class: "small muted" }, `${okd.length} OK'd · `, h("a", {
            href: "#",
            text: "show",
            onclick: (e) => {
              e.preventDefault();
              okdList.hidden = !okdList.hidden;
              e.target.textContent = okdList.hidden ? "show" : "hide";
            },
          }))
        : null;
      fill(
        box,
        h(
          "div",
          { class: "panel attention" + (grouped.length ? "" : " quiet") },
          h(
            "div",
            { class: "ph" },
            h("h2", { text: grouped.length ? `Needs attention (${grouped.length})` : "Nothing needs attention" }),
            grouped.length ? h("p", { text: "Most urgent first. Fix it, or press OK to hide it until something changes." }) : null,
          ),
          grouped.length ? h("ul", { class: "att-list" }, grouped.map((it, i) => Object.assign(line(it, [action(it), ok(it)]), { hidden: i >= 8 }))) : null,
          grouped.length > 8
            ? h("p", { class: "small muted" }, h("a", {
                href: "#",
                text: `show ${grouped.length - 8} more`,
                onclick: (e) => {
                  e.preventDefault();
                  e.target.closest(".attention").querySelectorAll(".att-list:not(.okd-list) li[hidden]").forEach((li) => (li.hidden = false));
                  e.target.parentNode.remove();
                },
              }))
            : null,
          okdToggle,
          okdList,
        ),
      );
    } catch (_) {}
  }

  async function loadSecrets(tries = 0) {
    const r = await api("GET", "/v1/secrets");
    S.secrets = r.secrets;
    drawSecrets();
    clearTimeout(S.pollTimer);
    if (S.secrets.some((m) => m.describe_status === "pending") && tries < 40) {
      S.pollTimer = setTimeout(() => loadSecrets(tries + 1).catch(() => {}), 1500);
    }
  }

  function drawSecrets() {
    const list = S.listEl;
    if (!list || !list.isConnected) return;
    if (!S.secrets.length) {
      list.replaceChildren(
        h(
          "div",
          { class: "empty" },
          h("p", { text: "No secrets yet. Add an API key and the vault works out what it is, checks it with its provider, and writes a description." }),
          h("button", { class: "btn primary", onclick: () => secretDialog(null), text: "Add your first secret" }),
        ),
      );
      return;
    }
    const q = S.filter.trim().toLowerCase();
    const shown = S.secrets.filter((m) => !q || m.name.toLowerCase().includes(q) || (m.description || "").toLowerCase().includes(q) || (m.notes || "").toLowerCase().includes(q));
    list.replaceChildren(...(shown.length ? shown.map(secretCard) : [h("p", { class: "muted", text: "Nothing matches that search." })]));
  }

  async function providers() {
    if (!S.providers) S.providers = (await api("GET", "/v1/providers")).providers;
    return S.providers;
  }

  function select(options, current) {
    const el = h("select", { class: "input" });
    for (const [v, label] of options) el.append(h("option", { value: v, text: label, selected: v === current ? true : null }));
    el.value = current == null ? "" : current;
    return el;
  }

  async function secretDialog(m) {
    const isNew = !m;
    let plist = [];
    try {
      plist = await providers();
    } catch (_) {}
    const name = h("input", { class: "input mono", required: true, maxlength: 128, pattern: "[A-Za-z0-9_.\\-]+", autocomplete: "off", spellcheck: "false", value: m ? m.name : "" });
    const value = h("textarea", {
      class: "input secret-input",
      rows: 3,
      required: isNew,
      autocomplete: "off",
      spellcheck: "false",
      placeholder: isNew ? "Paste the key" : "Leave blank to keep the current value",
    });
    const show = h("input", { type: "checkbox", onchange: (e) => value.classList.toggle("shown", e.target.checked) });
    const notes = h("textarea", { class: "input", rows: 2, maxlength: 4000, placeholder: "What it's for, which project uses it, who issued it…", value: m ? m.notes : "" });
    const tags = h("input", { class: "input", placeholder: "e.g. prod, billing", value: m ? (m.tags || []).join(", ") : "" });
    const verify = h("input", { type: "checkbox", checked: true });

    // Details: who can use it, what it is, how it rotates.
    const curProvider = m ? m.provider_hint || "" : "";
    const provider = select([["", "Work it out automatically"], ...plist.map((p) => [p.id, p.name])], curProvider);
    const kind = select([["", "Automatic"], ["api_key", "API key or token"], ["password", "Password"], ["private_key", "Private key"], ["other", "Other"]], m ? m.kind : "");
    const ownerOnly = h("input", { type: "checkbox", checked: m ? m.owner_only : false });
    const others = S.secrets.filter((x) => !m || x.name !== m.name);
    const parent = select([["", "None"], ...others.map((x) => [x.name, `${x.name}${x.provider_name ? " (" + x.provider_name + ")" : ""}`])], m ? m.parent || "" : "");
    const every = h("input", { class: "input", type: "number", min: 0, max: 3650, placeholder: "Off", value: m && m.rotate_every_days ? m.rotate_every_days : "" });
    const fieldBox = h("div", { class: "kv" });
    const partBox = h("div", {});
    const fieldInputs = new Map();
    const partInputs = new Map();
    const drawNeeds = () => {
      const pid = provider.value || (m && m.provider) || "";
      const p = plist.find((x) => x.id === pid);
      const needs = (p && p.needs) || [];
      const names = new Set([...Object.keys((m && m.fields) || {}), ...needs.filter((n) => !n.secret && n.name !== "base_url").map((n) => n.name)]);
      fieldInputs.clear();
      fieldBox.replaceChildren(
        ...[...names].map((n) => {
          const need = needs.find((x) => x.name === n);
          const inp = h("input", { class: "input mono", value: (m && m.fields && m.fields[n]) || "", placeholder: need ? need.hint : "" });
          fieldInputs.set(n, inp);
          return field("fld-" + n, need ? need.label : n.replace(/_/g, " "), inp);
        }),
      );
      partInputs.clear();
      const parts = new Set([...((m && m.parts) || []), ...needs.filter((n) => n.secret).map((n) => n.name)]);
      partBox.replaceChildren(
        ...[...parts].map((n) => {
          const need = needs.find((x) => x.name === n);
          const has = m && (m.parts || []).includes(n);
          const inp = h("input", { class: "input mono", type: "password", autocomplete: "off", placeholder: has ? "Stored. Leave blank to keep" : need ? need.hint : "" });
          partInputs.set(n, inp);
          return field("part-" + n, (need ? need.label : n.replace(/_/g, " ")) + " (secret)", inp);
        }),
      );
      const parentProvider = p && p.parent_provider;
      parentHint.textContent = (p && p.parent_hint ? `For rotation: ${p.parent_hint}.` : "Only needed for keys the vault can rotate through a managing key.") + " A manager becomes owner-only.";
      if (parentProvider) {
        for (const o of parent.options) o.hidden = !!o.value && !S.secrets.some((x) => x.name === o.value && x.provider === parentProvider);
      }
    };
    const parentHint = h("span", { class: "hint" });
    provider.addEventListener("change", drawNeeds);
    const newField = h("button", {
      class: "btn ghost",
      type: "button",
      text: "Add a field",
      onclick: () => {
        const k = (prompt("Field name (lowercase, e.g. account_id)") || "").trim();
        if (!/^[a-z][a-z0-9_]{0,39}$/.test(k) || fieldInputs.has(k)) return;
        const inp = h("input", { class: "input mono" });
        fieldInputs.set(k, inp);
        fieldBox.append(field("fld-" + k, k.replace(/_/g, " "), inp));
        inp.focus();
      },
    });

    const fields = [
      field("f-name", "Name", name, "Letters, digits, _ - and . (e.g. OPENAI_API_KEY). Apps use this name."),
      field("f-value", isNew ? "Value" : "New value", value),
      h("label", { class: "check" }, show, "Show value while typing"),
      field("f-notes", "Notes", notes),
      field("f-tags", "Tags", tags, "Comma-separated."),
      h("label", { class: "check" }, verify, h("span", {}, "Check the key with its provider. ", h("span", { class: "hint", text: "The key is sent only to that provider's own API, to learn the account and scopes." }))),
      h(
        "details",
        { class: "more", open: m && (m.owner_only || m.parent || Object.keys(m.fields || {}).length) ? true : null },
        h("summary", { text: "Details: service, who can use it, linked parts, rotation" }),
        h("label", { class: "check" }, ownerOnly, h("span", {}, h("b", { text: "Only me" }), " — ", h("span", { class: "hint", text: "No token can list, read or use this through the proxy, whatever its scopes. Good for passwords and wallet keys." }))),
        field("f-provider", "Service", provider, "Set this if the vault guessed wrong."),
        field("f-kind", "Kind", kind),
        fieldBox,
        h("p", {}, newField),
        partBox,
        field("f-parent", "Manager", parent),
        parentHint,
        field("f-every", "Rotate every (days)", every, "Leave empty for no schedule. Keys that can rotate automatically are rotated on this schedule; others are flagged when due."),
      ),
    ];
    let base, authSpec;
    if (!isNew) {
      base = h("input", { class: "input mono", placeholder: "Provider default", value: m.proxy_base_url || "" });
      authSpec = h("input", { class: "input mono", placeholder: "Provider default", value: m.proxy_auth || "" });
      fields.push(
        h(
          "fieldset",
          {},
          h("legend", { text: "Proxy (optional)" }),
          field("f-base", "Base URL", base, "Where /v1/proxy/" + m.name + "/… requests go. Must be https."),
          field("f-auth", "How the key is sent", authSpec, "bearer, basic, basic:<part>, header:<name>, query:<param> or headers:<Name>={part};…"),
        ),
      );
    }
    drawNeeds();
    openDialog(isNew ? "Add secret" : "Edit " + m.name, fields, isNew ? "Add secret" : "Save changes", async () => {
      const tagList = tags.value.split(",").map((t) => t.trim()).filter(Boolean);
      const fieldMap = {};
      for (const [k, inp] of fieldInputs) if (inp.value.trim()) fieldMap[k] = inp.value.trim();
      const extras = [];
      for (const [k, inp] of partInputs) if (inp.value) extras.push({ name: k, value: inp.value });
      const settings = {};
      if (provider.value !== curProvider) settings.provider = provider.value;
      if (kind.value && kind.value !== (m ? m.kind : "")) settings.kind = kind.value;
      if (ownerOnly.checked !== (m ? m.owner_only : false)) settings.owner_only = ownerOnly.checked;
      if (parent.value !== (m ? m.parent || "" : "")) settings.parent = parent.value;
      const ev = every.value === "" ? 0 : Number(every.value);
      if (ev !== ((m && m.rotate_every_days) || 0) || (isNew && every.value !== "")) settings.rotate_every_days = ev;
      if (JSON.stringify(fieldMap) !== JSON.stringify((m && m.fields) || {})) settings.fields = fieldMap;
      let res;
      if (isNew) {
        res = await api("POST", "/v1/secrets", { name: name.value.trim(), value: value.value, notes: notes.value, tags: tagList, verify: verify.checked, extras, ...settings });
        toast(`Added ${name.value.trim()}. Working out what it is…`);
      } else {
        const body = { notes: notes.value, tags: tagList, verify: verify.checked, ...settings };
        if (name.value.trim() !== m.name) body.name = name.value.trim();
        if (value.value.trim()) body.value = value.value;
        if (extras.length) body.extras = extras;
        if (base.value.trim() !== (m.proxy_base_url || "") || authSpec.value.trim() !== (m.proxy_auth || "")) {
          body.proxy = { base_url: base.value.trim(), auth: authSpec.value.trim() };
        }
        res = await api("PATCH", `/v1/secrets/${encodeURIComponent(m.name)}`, body);
        toast(`Saved ${body.name || m.name}.`);
      }
      if (res && res.duplicate_of) toast(`Note: ${res.duplicate_of} holds the same value.`, true);
      value.value = "";
      for (const inp of partInputs.values()) inp.value = "";
      await loadSecrets();
    });
  }

  // ---------------------------------------------------------------- rotate dialog

  const ROT_STATE = {
    running: ["info", "Running"],
    grace: ["good", "Switched; old key revoked soon"],
    manual_revoke: ["warn", "Switched; delete the old key"],
    done: ["good", "Done"],
    failed: ["crit", "Failed"],
    rolled_back: ["info", "Undone"],
  };
  function rotStatus(r) {
    const [cls, label] = ROT_STATE[r.state] || ["info", r.state];
    return h("span", { class: "status " + cls, title: r.message || "" }, h("span", { class: "dot", "aria-hidden": "true" }), label);
  }

  async function undoRotation(id) {
    if (!confirm("Undo this rotation? The previous value becomes current again, and a key the vault created is revoked.")) return false;
    await api("POST", `/v1/rotations/${id}/rollback`);
    toast("Rotation undone. The previous value is current again.");
    return true;
  }

  function rotateDialog(m, onDone) {
    const r = m.rotation || {};
    const dlg = h("dialog", { class: "rotate" });
    const body = h("div", {});
    const err = h("p", { class: "form-error", role: "alert" });
    const close = () => {
      dlg.close();
      dlg.remove();
    };
    const pname = m.provider_name || "the provider";
    const short = pname.replace(/ \(.*\)| (API key|API token|token|key|client secret|private key.*|refresh token.*|management key)$/gi, "").trim() || pname;
    const link = safeUrl(r.rotate_url);
    const openLink = (label) => (link ? h("a", { class: "btn", href: link, target: "_blank", rel: "noopener noreferrer", text: label || `Open ${short} ↗` }) : null);
    const grace = (S.status.rotation || {}).grace_hours || 24;

    function showResult(res) {
      const rot = res.rotation;
      const lines = {
        grace: `Done. Apps now use the new key. The old one keeps working for ${grace} hours, then the vault revokes it.`,
        done: "Done. Apps now use the new key. " + (rot.message ? rot.message.charAt(0).toUpperCase() + rot.message.slice(1) + "." : ""),
        manual_revoke: "Done. Apps now use the new key. Last step: delete the old key on the provider's site.",
      };
      fill(
        body,
        h("p", {}, rotStatus(rot)),
        h("p", { text: lines[rot.state] || rot.message || "" }),
        rot.state === "manual_revoke"
          ? [
              h("p", {}, openLink(`Open ${short} to delete the old key ↗`)),
              h("button", {
                class: "btn primary",
                type: "button",
                text: "I've deleted the old key",
                onclick: async () => {
                  try {
                    await api("POST", `/v1/rotations/${rot.id}/done`);
                    toast("Marked done. The old value has been erased from the vault.");
                    close();
                    onDone && onDone();
                  } catch (e) {
                    err.textContent = e.message;
                  }
                },
              }),
            ]
          : null,
        ["grace", "manual_revoke"].includes(rot.state)
          ? h(
              "p",
              { class: "small muted" },
              "Something broke? ",
              h("button", {
                class: "btn ghost",
                type: "button",
                text: "Undo this rotation",
                onclick: async () => {
                  try {
                    if (await undoRotation(rot.id)) {
                      close();
                      onDone && onDone();
                    }
                  } catch (e) {
                    err.textContent = e.message;
                  }
                },
              }),
            )
          : null,
      );
      onDone && onDone();
    }

    const steps = r.steps && r.steps.length ? r.steps : ["Create a new value where this one came from.", "Paste it here.", "Delete or disable the old one there."];
    function guided(intro) {
      const val = h("textarea", { class: "input secret-input shown", rows: 3, autocomplete: "off", spellcheck: "false", placeholder: "Paste the new key", required: true });
      const needs = (r.needs || []).filter((n) => n.name !== "base_url");
      const inputs = needs.map((n) => {
        const inp = h("input", { class: "input mono", type: n.secret ? "password" : "text", autocomplete: "off", placeholder: n.secret ? "Leave blank if unchanged" : (m.fields && m.fields[n.name]) || n.hint });
        if (!n.secret && m.fields && m.fields[n.name]) inp.value = m.fields[n.name];
        return [n, inp];
      });
      const skip = h("input", { type: "checkbox" });
      const submit = h("button", { class: "btn primary", type: "submit", text: "Check it and switch over" });
      return h(
        "form",
        {
          onsubmit: async (e) => {
            e.preventDefault();
            err.textContent = "";
            submit.disabled = true;
            submit.textContent = "Checking…";
            const fields = {};
            const extras = [];
            for (const [n, inp] of inputs) {
              if (n.secret) {
                if (inp.value) extras.push({ name: n.name, value: inp.value });
              } else if (inp.value.trim()) fields[n.name] = inp.value.trim();
            }
            try {
              const res = await api("POST", `/v1/secrets/${encodeURIComponent(m.name)}/rotate`, { value: val.value, fields: Object.keys(fields).length ? { ...(m.fields || {}), ...fields } : undefined, extras, skip_check: skip.checked });
              val.value = "";
              showResult(res);
            } catch (ex) {
              err.textContent = ex.message;
              submit.disabled = false;
              submit.textContent = "Check it and switch over";
            }
          },
        },
        intro ? h("p", { text: intro }) : null,
        h("ol", { class: "steps" }, steps.map((t) => h("li", { text: t }))),
        link ? h("p", {}, openLink()) : null,
        field("rot-value", "New key", val),
        inputs.map(([n, inp]) => field("rot-" + n.name, n.label + (n.secret ? " (if it changed)" : ""), inp, n.secret ? null : "Update this if the provider gave you a new one.")),
        h("details", { class: "more" }, h("summary", { text: "Can't be checked?" }), h("label", { class: "check" }, skip, h("span", { class: "hint", text: "Store it even if the provider can't confirm it works (for example, the service is down)." }))),
        h("p", { class: "small muted", text: r.revokes_old ? `After you switch over, the vault disables the old key itself after ${grace} hours.` : "After you switch over, delete the old key on the provider's site." }),
        submit,
      );
    }

    if (r.mode === "never") {
      fill(body, h("p", { text: r.never_reason || "This can't be rotated." }));
    } else if (r.mode === "minted") {
      fill(
        body,
        h("p", { text: "Nothing to do on a schedule: every time an app uses this through the vault, it gets a short-lived token made from it, which expires on its own." }),
        h("details", { class: "more" }, h("summary", { text: "Replace the underlying credential anyway" }), guided(null)),
      );
    } else if (r.mode === "auto" && r.ready) {
      const go = h("button", {
        class: "btn primary",
        type: "button",
        text: "Rotate now",
        onclick: async () => {
          err.textContent = "";
          go.disabled = true;
          go.textContent = "Rotating…";
          try {
            showResult(await api("POST", `/v1/secrets/${encodeURIComponent(m.name)}/rotate`, {}));
          } catch (e) {
            err.textContent = e.message;
            go.disabled = false;
            go.textContent = "Try again";
          }
        },
      });
      fill(
        body,
        h("p", { text: `The vault does this for you: it creates a new key at ${short}${m.parent ? " using " + m.parent : ""}, checks it works, switches every app over, then revokes the old key after ${grace} hours.` }),
        h("p", {}, go),
        h("details", { class: "more" }, h("summary", { text: "Or do it by hand" }), guided(null)),
      );
    } else if (r.mode === "auto" && (r.missing || []).length) {
      fill(
        body,
        h("p", {}, "This can rotate automatically once it has these details: ", h("b", { text: r.missing.join(", ") }), "."),
        h("p", {}, h("button", { class: "btn", type: "button", text: "Add them", onclick: () => { close(); secretDialog(m); } })),
        h("hr"),
        guided("Or rotate it by hand now:"),
      );
    } else if (r.mode === "auto") {
      const cands = S.secrets.filter((x) => x.provider && x.provider === r.parent_provider && x.name !== m.name);
      const pick = select([["", "Choose…"], ...cands.map((x) => [x.name, x.name])], "");
      const save = h("button", {
        class: "btn",
        type: "button",
        text: "Use it",
        onclick: async () => {
          if (!pick.value) return;
          try {
            const updated = await api("PATCH", `/v1/secrets/${encodeURIComponent(m.name)}`, { parent: pick.value });
            close();
            rotateDialog(updated, onDone);
          } catch (e) {
            err.textContent = e.message;
          }
        },
      });
      fill(
        body,
        r.manager_problem ? h("p", { class: "status warn" }, h("span", { class: "dot" }), "The current manager can't be used: " + r.manager_problem + ".") : null,
        h("p", {}, "This can rotate automatically once it has a manager: ", h("b", { text: r.parent_hint || "a managing key" }), ". The manager becomes owner-only, so no token can use or change it."),
        cands.length ? h("div", { class: "row" }, pick, save) : h("p", { class: "small muted", text: "Add one to the vault first, then come back here." }),
        h("hr"),
        guided("Or rotate it by hand now:"),
      );
    } else {
      fill(body, guided(null));
    }

    dlg.append(
      h("h2", { text: "Rotate " + m.name }),
      h("p", { class: "small muted", text: `${pname} · ${rotationLine(m)}` }),
      body,
      err,
      h("div", { class: "buttons" }, h("button", { class: "btn", type: "button", onclick: close, text: "Close" })),
    );
    dlg.addEventListener("cancel", () => setTimeout(() => dlg.remove()));
    document.body.append(dlg);
    dlg.showModal();
  }

  function deleteDialog(m) {
    const confirmName = h("input", { class: "input mono", autocomplete: "off", spellcheck: "false" });
    openDialog(
      "Delete " + m.name + "?",
      [
        h("p", { class: "note error-box", text: "The encrypted value and all its old versions are erased. Apps using it will start failing. This doesn't revoke the key at the provider, so do that too if it may have leaked." }),
        field("f-confirm", "Type the name to confirm", confirmName),
      ],
      "Delete",
      async () => {
        if (confirmName.value.trim() !== m.name) throw new Error("The name doesn't match.");
        await api("DELETE", `/v1/secrets/${encodeURIComponent(m.name)}`);
        toast(`Deleted ${m.name}.`);
        await loadSecrets();
      },
      true,
    );
  }

  // ---------------------------------------------------------------- rotation page

  const MODES = [
    ["auto", "The vault rotates these itself", "It creates the new key through the provider's API, checks it works, switches your apps over and revokes the old key a day later. Each needs a manager: the key that's allowed to create new ones."],
    ["guided", "You make the new key, the vault does the rest", "Open the provider's page from the button, create a key, paste it here. The vault checks it, switches your apps over and tells you when to delete the old one."],
    ["minted", "These renew themselves", "Apps get short-lived tokens made from these, which expire within hours. Nothing to rotate on a schedule."],
    ["never", "These can't be rotated", "Follow the advice on each one instead."],
  ];

  function rotationView() {
    const out = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
    async function load() {
      try {
        const [sec, rot] = await Promise.all([api("GET", "/v1/secrets"), api("GET", "/v1/rotations")]);
        S.secrets = sec.secrets;
        if (!out.isConnected) return;
        draw(rot.rotations);
      } catch (e) {
        out.replaceChildren(errBox(e));
      }
    }
    function statusFor(m) {
      const r = m.rotation || {};
      if (m.exposed) return h("span", { class: "status crit", title: m.exposed }, h("span", { class: "dot" }), "Exposed: replace first");
      if (m.expires_at && m.expires_at < Date.now()) return h("span", { class: "status crit" }, h("span", { class: "dot" }), "Expired");
      if (r.next_due && r.next_due < Date.now() && r.mode !== "minted") return h("span", { class: "status warn" }, h("span", { class: "dot" }), "Due");
      if (r.mode === "auto" && (r.missing || []).length) return h("span", { class: "status warn", title: r.missing.join(", ") }, h("span", { class: "dot" }), "Needs details");
      if (r.mode === "auto" && r.manager_problem) return h("span", { class: "status warn", title: r.manager_problem }, h("span", { class: "dot" }), "Manager problem");
      if (r.mode === "auto" && !r.ready) return h("span", { class: "status warn", title: r.parent_hint || "" }, h("span", { class: "dot" }), "Needs a manager");
      return h("span", { class: "status good" }, h("span", { class: "dot" }), "OK");
    }
    const urgency = (m) => (m.exposed ? 0 : m.expires_at && m.expires_at < Date.now() ? 1 : m.rotation && m.rotation.next_due && m.rotation.next_due < Date.now() ? 2 : 3);
    function draw(rotations) {
      const groups = MODES.map(([mode, title, explain]) => {
        const items = S.secrets.filter((m) => (m.rotation || {}).mode === mode).sort((a, b) => urgency(a) - urgency(b) || a.name.localeCompare(b.name));
        if (!items.length) return null;
        const rows = items.map((m) => {
          const r = m.rotation || {};
          const link = safeUrl(r.rotate_url);
          return [
            h("span", { class: "mono", text: m.name }),
            m.provider_name || "Unknown",
            statusFor(m),
            h("span", { class: "nowrap", title: when(m.rotated_at), text: m.rotated_at ? ago(m.rotated_at) : "never" }),
            h("span", { class: "nowrap", text: r.next_due && mode !== "minted" && mode !== "never" ? dueText(r.next_due) : "" }),
            h(
              "span",
              { class: "row-actions" },
              mode === "never"
                ? h("span", { class: "small muted", text: r.never_reason || "" })
                : h("button", { class: "btn" + (urgency(m) < 3 ? " primary" : ""), type: "button", text: mode === "auto" && r.ready ? "Rotate now" : mode === "auto" ? "Set up" : "Rotate", onclick: () => rotateDialog(m, load) }),
              link && mode !== "never" ? h("a", { href: link, target: "_blank", rel: "noopener noreferrer", text: "Provider page ↗" }) : null,
            ),
          ];
        });
        return panel(title, explain, table([["Secret"], ["Service"], ["Status"], ["Last rotated"], ["Next"], [""]], rows, "", true));
      });
      const recent = table(
        [["When"], ["Secret"], ["How"], ["Result"], ["Who"], [""]],
        rotations.slice(0, 30).map((x) => [
          h("span", { class: "nowrap", title: when(x.started_at), text: ago(x.started_at) }),
          h("span", { class: "mono", text: x.secret }),
          x.mode === "auto" ? "automatic" : "by hand",
          h("span", {}, rotStatus(x), x.message ? h("div", { class: "small muted", text: x.message }) : null),
          x.actor,
          h(
            "span",
            { class: "row-actions" },
            x.state === "manual_revoke"
              ? h("button", {
                  class: "btn",
                  type: "button",
                  text: "Old key deleted",
                  onclick: async () => {
                    try {
                      await api("POST", `/v1/rotations/${x.id}/done`);
                      toast("Marked done.");
                      load();
                    } catch (e) {
                      toast(e.message, true);
                    }
                  },
                })
              : null,
            ["grace", "manual_revoke"].includes(x.state)
              ? h("button", {
                  class: "btn ghost",
                  type: "button",
                  text: "Undo",
                  onclick: async () => {
                    try {
                      if (await undoRotation(x.id)) load();
                    } catch (e) {
                      toast(e.message, true);
                    }
                  },
                })
              : null,
          ),
        ]),
        "No rotations yet.",
        true,
      );
      const st = S.status.rotation || {};
      fill(
        out,
        h(
          "div",
          { class: "note" },
          `Rotating means swapping a key for a new one, so a copy that leaked stops working. Apps that call providers through the vault's proxy switch over instantly. Apps that fetched the raw value get ${st.grace_hours || 24} hours to fetch it again before the old key is revoked. `,
          st.scheduled ? "Scheduled rotation is on." : "Scheduled rotation is off in the config.",
        ),
        groups,
        panel("Recent rotations", "Undo works until the old key is revoked", recent),
      );
    }
    load();
    return h("section", {}, head("Rotation", "Replace keys before they leak, or right after. Exposed ones first."), out);
  }

  // ---------------------------------------------------------------- import page

  function importView() {
    const text = h("textarea", { class: "input mono secret-input shown", rows: 10, autocomplete: "off", spellcheck: "false", placeholder: "Paste a .env file or your notes, e.g.\nStripe live - sk_live_...\nOPENAI_API_KEY=sk-..." });
    const file = h("input", { type: "file", accept: ".txt,.env,.md,text/plain" });
    const err = h("p", { class: "form-error", role: "alert" });
    const out = h("div", {});
    file.addEventListener("change", async () => {
      const f = file.files && file.files[0];
      if (!f) return;
      if (f.size > 1024 * 1024) return (err.textContent = "That file is larger than 1 MiB.");
      text.value = await f.text();
      file.value = "";
    });
    const btn = h("button", { class: "btn primary", type: "submit", text: "Preview" });
    const form = h(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          if (!text.value.trim()) return (err.textContent = "Paste something first.");
          btn.disabled = true;
          try {
            const r = await api("POST", "/v1/import/preview", { text: text.value });
            // The server keeps the values for the next step; don't leave them on the page.
            text.value = "";
            drawPreview(r);
          } catch (ex) {
            err.textContent = ex.message;
          } finally {
            btn.disabled = false;
          }
        },
      },
      field("imp-text", "Key file", text, "Nothing is saved until you review the list and click Import. Values are never shown again in this page."),
      h("p", {}, h("label", { class: "small" }, "Or choose a file: ", file)),
      err,
      btn,
    );

    function drawPreview(r) {
      const rows = r.items.map((it) => {
        const inc = h("input", { type: "checkbox", checked: it.include, "aria-label": "Import line " + it.line });
        const name = h("input", { class: "input mono compact", value: it.name, "aria-label": "Name for line " + it.line });
        const owner = h("input", { type: "checkbox", checked: it.owner_only, "aria-label": "Only me" });
        const needs = it.needs.map((n) => [n, h("input", { class: "input mono compact", type: n.secret ? "password" : "text", autocomplete: "off", placeholder: n.label, title: n.hint })]);
        return { it, inc, name, owner, needs };
      });
      const exposed = h("input", { type: "checkbox", checked: true });
      const results = h("div", {});
      const go = h("button", { class: "btn primary", type: "button", text: "Import selected" });
      go.addEventListener("click", async () => {
        go.disabled = true;
        try {
          const items = rows.map(({ it, inc, name, owner, needs }) => {
            const fields = {};
            const extras = [];
            let base_url;
            for (const [n, inp] of needs) {
              const v = inp.value.trim();
              if (!v) continue;
              if (n.name === "base_url") base_url = v;
              else if (n.secret) extras.push({ name: n.name, value: v });
              else fields[n.name] = v;
            }
            return { id: it.id, include: inc.checked, name: name.value.trim(), owner_only: owner.checked, parent: it.parent || undefined, fields, extras, base_url };
          });
          const res = await api("POST", "/v1/import/commit", { import_id: r.import_id, items, mark_exposed: exposed.checked });
          for (const { needs } of rows) for (const [, inp] of needs) inp.value = "";
          drawDone(res);
        } catch (e) {
          toast(e.message, true);
          go.disabled = false;
        }
      });
      const tbl = table(
        [["Import"], ["Line", 1], ["Name"], ["Service"], ["Value"], ["Only me"], ["Also needs"], ["Notes"]],
        rows.map(({ it, inc, name, owner, needs }) => [
          inc,
          String(it.line),
          name,
          h("span", {}, it.provider_name || "Unknown", " ", riskBadge(it.risk)),
          h("span", { class: "mono small nowrap", text: it.preview }),
          owner,
          needs.length ? h("div", { class: "needs" }, needs.map(([, inp]) => inp)) : "",
          h(
            "span",
            { class: "small" },
            it.duplicate_of ? h("div", { class: "muted", text: "Same value as " + it.duplicate_of }) : null,
            it.parent ? h("div", { class: "muted", text: "Managed by " + it.parent }) : null,
            it.rotation === "auto" ? h("div", { class: "muted", text: "Can rotate automatically" }) : null,
            it.label ? h("div", { class: "muted", title: it.label, text: "“" + it.label.slice(0, 60) + "”" }) : null,
          ),
        ]),
        "No keys found in that text.",
        true,
      );
      fill(
        out,
        panel(
          `Found ${plural(r.items.length, "key")}`,
          `${r.items.filter((x) => !x.include).length} duplicate(s) unticked. Check the names: apps will use them.`,
          h(
            "div",
            {},
            tbl,
            r.unmatched.length
              ? h(
                  "div",
                  { class: "note" },
                  h("b", { text: "Lines that looked like a label but had no value next to them: " }),
                  h("ul", {}, r.unmatched.map((u) => h("li", {}, `line ${u.line}: `, h("span", { class: "mono", text: u.text })))),
                )
              : null,
            h("label", { class: "check" }, exposed, h("span", {}, h("b", { text: "Flag these as exposed" }), " — ", h("span", { class: "hint", text: "They sat in a plain text file, so treat them as leaked until you replace them. The flag clears when you rotate each one." }))),
            h("p", {}, go),
            results,
          ),
        ),
      );
    }

    function drawDone(res) {
      fill(
        out,
        panel(
          `Imported ${plural(res.created, "secret")}`,
          res.failed ? `${res.failed} failed: see below.` : "Each one is being checked with its provider and described now.",
          h(
            "div",
            {},
            table(
              [["Name"], ["Result"]],
              res.results.map((x) => [
                h("span", { class: "mono", text: x.name }),
                x.status === "created"
                  ? h("span", { class: "status good" }, h("span", { class: "dot" }), "Imported", x.duplicate_of ? ` (same value as ${x.duplicate_of})` : "")
                  : x.status === "skipped"
                    ? h("span", { class: "muted", text: "Skipped" })
                    : h("span", { class: "status crit" }, h("span", { class: "dot" }), x.error || "Failed"),
              ]),
              "",
            ),
            h(
              "div",
              { class: "note" },
              h("b", { text: "Next steps" }),
              h(
                "ol",
                { class: "steps" },
                h("li", {}, "Delete the file you imported from, everywhere it exists: ", h("code", { text: "shred -u keys.txt" }), " (and any copies in notes apps or cloud folders)."),
                h("li", {}, "Open ", h("a", { href: "#/rotation", text: "Rotation" }), " and replace the exposed keys, highest risk first."),
                h("li", {}, "Point your apps at the vault instead of their own copies (Tokens page)."),
              ),
            ),
          ),
        ),
      );
    }

    return h(
      "section",
      {},
      head("Import", "Bring in a whole file of keys at once. The vault works out what each one is, suggests names, and links keys that belong together."),
      panel("Paste or choose a file", null, form),
      out,
    );
  }

  // ---------------------------------------------------------------- dashboard

  const RANGES = { "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days" };

  function dashboardView() {
    const body = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
    const updated = h("span", { class: "muted small" });
    const btns = Object.entries(RANGES).map(([k, label]) =>
      h("button", {
        class: "seg-btn",
        type: "button",
        "aria-pressed": String(S.range === k),
        text: label,
        onclick: () => {
          S.range = k;
          btns.forEach((b) => b.setAttribute("aria-pressed", String(b.textContent === label)));
          load();
        },
      }),
    );
    async function load() {
      try {
        const d = await api("GET", `/v1/dashboard?range=${S.range}`);
        if (!body.isConnected) return;
        drawDashboard(body, d);
        updated.textContent = "Updated " + new Date().toLocaleTimeString() + " · refreshes every 30s";
      } catch (e) {
        body.replaceChildren(errBox(e));
      }
    }
    load();
    S.timer = setInterval(load, 30000);
    return h(
      "section",
      {},
      head("Dashboard", "Which secrets were used, how often, from which machines, and how fast."),
      h("div", { class: "filters" }, h("div", { class: "seg", role: "group", "aria-label": "Time range" }, btns), updated),
      body,
    );
  }

  function tile(label, value, status) {
    return h(
      "div",
      { class: "tile" + (status ? " " + status : "") },
      h("div", { class: "k" }, status ? h("span", { class: "dot", "aria-hidden": "true" }) : null, label),
      h("div", { class: "v", text: value }),
    );
  }

  function panel(title, sub, content, extra) {
    return h("div", { class: "panel" }, h("div", { class: "ph" }, h("h2", { text: title }), sub ? h("p", { text: sub }) : null), extra, content);
  }

  function table(cols, rows, empty, stack) {
    if (!rows.length) return h("p", { class: "muted small", text: empty || "No activity in this range." });
    return h(
      "div",
      { class: "table-wrap" + (stack ? " stack" : "") },
      h(
        "table",
        {},
        h("thead", {}, h("tr", {}, cols.map(([label, numeric]) => h("th", { class: numeric ? "num" : null, scope: "col", text: label })))),
        h("tbody", {}, rows.map((r) => h("tr", {}, r.map((cell, i) => h("td", { class: cols[i][1] ? "num" : null, "data-label": cols[i][0] }, cell))))),
      ),
    );
  }

  // Mirrors dashboard::is_denied on the server.
  function isDenied(e) {
    return e.action === "denied" || (e.detail || "").includes("denied") || ((e.action === "login" || e.action === "vault.setup") && [401, 403, 429].includes(e.status));
  }
  function statusCell(e) {
    const code = e.status;
    let cls = "good", label = "OK";
    if (code === 429) [cls, label] = ["warn", "Locked out"];
    else if (isDenied(e)) [cls, label] = ["warn", "Denied"];
    else if (code >= 400) [cls, label] = ["crit", e.upstream_us ? "Provider error" : "Failed"];
    return h("span", { class: "status " + cls }, h("span", { class: "dot", "aria-hidden": "true" }), `${label} ${code}`);
  }

  function makeTip(container) {
    const tip = h("div", { class: "tip", role: "tooltip" });
    container.append(tip);
    return {
      show(evt, nodes) {
        tip.replaceChildren(...nodes);
        tip.classList.add("on");
        const box = container.getBoundingClientRect();
        let x = evt.clientX - box.left + 12;
        const y = evt.clientY - box.top - 12;
        const w = tip.offsetWidth;
        if (x + w > box.width) x = Math.max(4, evt.clientX - box.left - w - 12);
        tip.style.left = x + "px";
        tip.style.top = Math.max(0, y - tip.offsetHeight) + "px";
      },
      hide() {
        tip.classList.remove("on");
      },
    };
  }

  function niceMax(v) {
    const p = Math.pow(10, Math.floor(Math.log10(Math.max(1, v))));
    for (const m of [1, 2, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  // Rounded at the data end (top) only, square on the baseline.
  function barPath(x, y, w, hgt, r) {
    r = Math.max(0, Math.min(r, w / 2, hgt));
    return `M${x},${y + hgt}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + hgt}Z`;
  }

  function timelineChart(d) {
    const holder = h("div", { class: "chart-svg" });
    const wrap = h(
      "div",
      {},
      h("div", { class: "legend" }, h("span", {}, h("i", { class: "s1" }), "Succeeded"), h("span", {}, h("i", { class: "crit" }), "Failed or denied")),
      holder,
    );
    const total = d.timeline.reduce((a, b) => a + b.ok + b.errors, 0);
    const draw = () => {
      const W = Math.max(260, holder.clientWidth || 600);
      const H = 210;
      const m = { l: 40, r: 6, t: 10, b: 24 };
      const iw = W - m.l - m.r;
      const ih = H - m.t - m.b;
      const n = d.timeline.length;
      const top = niceMax(Math.max(1, ...d.timeline.map((b) => b.ok + b.errors)));
      const y = (v) => m.t + ih - (v / top) * ih;
      const band = iw / n;
      const bw = Math.max(2, Math.min(28, band - 2));
      const svgEl = s("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img", "aria-label": `${num(total)} requests, ${RANGES[d.range].toLowerCase()}` });
      const ticks = top >= 2 ? [0, top / 2, top] : [0, top];
      for (const v of ticks) {
        svgEl.append(s("line", { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: v === 0 ? "axis" : "grid" }));
        svgEl.append(s("text", { x: m.l - 6, y: y(v) + 4, "text-anchor": "end", class: "tick" }, num(v)));
      }
      // Hit targets span the full column, wider than the bar itself.
      d.timeline.forEach((b, i) => {
        const hit = s("rect", { x: m.l + i * band, y: m.t, width: band, height: ih, fill: "transparent", class: "hit" });
        const showIt = (e) => {
          const end = new Date(b.t + d.bucket_ms);
          tip.show(e, [
            h("b", { text: `${fmtBucket(b.t, d.bucket_ms)} – ${fmtBucket(end.getTime(), d.bucket_ms)}` }),
            h("br"),
            `${num(b.ok)} succeeded · ${num(b.errors)} failed`,
          ]);
        };
        hit.addEventListener("mousemove", showIt);
        hit.addEventListener("mouseleave", () => tip.hide());
        svgEl.append(hit);
      });
      d.timeline.forEach((b, i) => {
        const x = m.l + i * band + (band - bw) / 2;
        if (b.ok) svgEl.append(s("path", { d: barPath(x, y(b.ok), bw, y(0) - y(b.ok), b.errors ? 0 : 4), class: "s1" }));
        if (b.errors) {
          const base = b.ok ? y(b.ok) - 2 : y(0);
          const hgt = y(0) - y(b.errors);
          svgEl.append(s("path", { d: barPath(x, base - hgt, bw, hgt, 4), class: "crit-fill" }));
        }
      });
      const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 80))));
      d.timeline.forEach((b, i) => {
        if (i % every) return;
        svgEl.append(s("text", { x: m.l + i * band + band / 2, y: H - 6, "text-anchor": "middle", class: "tick" }, fmtBucket(b.t, d.bucket_ms)));
      });
      holder.replaceChildren(svgEl);
    };
    const tip = makeTip(wrap);
    wrap.style.position = "relative";
    requestAnimationFrame(draw);
    let last = 0;
    const ro = new ResizeObserver(() => {
      const w = holder.clientWidth;
      if (Math.abs(w - last) > 4) {
        last = w;
        draw();
      }
    });
    ro.observe(holder);
    S.observers.push(ro);
    return wrap;
  }

  function barList(items, empty) {
    if (!items.length) return h("p", { class: "muted small", text: empty });
    const wrap = h("div", { class: "bars" });
    const max = Math.max(1, ...items.map((i) => i.value));
    const tip = makeTip(wrap);
    wrap.style.position = "relative";
    for (const it of items) {
      const bar = h("span", { class: "bar" });
      bar.style.width = (it.value / max) * 100 + "%";
      const row = h("div", { class: "bar-row", tabindex: "0", "aria-label": `${it.label}: ${it.value}` }, h("span", { class: "bar-label", text: it.label }), h("span", { class: "bar-track" }, bar), h("span", { class: "bar-value num", text: num(it.value) }));
      row.addEventListener("mousemove", (e) => tip.show(e, it.tip));
      row.addEventListener("mouseleave", () => tip.hide());
      wrap.append(row);
    }
    return wrap;
  }

  function drawDashboard(body, d) {
    // Drop the old charts' resize observers; the refresh interval keeps running.
    S.observers.forEach((o) => o.disconnect());
    S.observers = [];
    const t = d.totals;
    const kpis = h(
      "div",
      { class: "kpis" },
      tile("Requests", num(t.requests)),
      tile("Failed", num(t.errors), t.errors ? "crit" : null),
      tile("Denied", num(t.denied), t.denied ? "warn" : null),
      tile("Machines", num(t.machines)),
      tile("Secrets used", num(t.secrets_used)),
      tile("p95 latency", fmtMs(t.p95_ms)),
      d.attention ? tile("Needs attention", num(d.attention.total), d.attention.critical ? "crit" : d.attention.total ? "warn" : null) : null,
    );
    const secretBars = barList(
      d.by_secret.slice(0, 10).map((x) => ({
        label: x.secret,
        value: x.count,
        tip: [
          h("b", { text: x.secret }),
          h("br"),
          Object.entries(x.actions).map(([a, n]) => `${a} ×${n}`).join(", "),
          h("br"),
          "From " + x.machines.join(", ") + " · last " + ago(x.last_used),
        ],
      })),
      "No secret was used in this range.",
    );
    const machines = table(
      [["Machine"], ["Tailscale user"], ["Requests", 1], ["Secrets", 1], ["Denied", 1], ["Last seen", 1]],
      d.by_machine.map((m) => [h("span", { class: "mono", text: m.node }), m.user, num(m.count), num(m.secrets), m.denied ? h("span", { class: "status warn" }, h("span", { class: "dot" }), num(m.denied)) : "0", h("span", { title: when(m.last_seen), text: ago(m.last_seen) })]),
    );
    const latCols = [["Operation"], ["Count", 1], ["p50", 1], ["p95", 1], ["p99", 1], ["Max", 1]];
    const lat = (rows, mono) => rows.map((r) => [h("span", { class: mono ? "mono" : null, text: r.key }), num(r.count), fmtMs(r.p50_ms), fmtMs(r.p95_ms), fmtMs(r.p99_ms), fmtMs(r.max_ms)]);
    const recent = table(
      [["When"], ["Machine"], ["Who"], ["Action"], ["Secret"], ["Result"], ["Latency", 1]],
      d.recent.map((e) => [
        h("span", { class: "nowrap", title: when(e.ts), text: ago(e.ts) }),
        h("span", { class: "mono", text: e.node }),
        e.actor,
        h("span", { title: e.detail || "", text: e.action + (e.detail ? " · " + e.detail : "") }),
        e.secret ? h("span", { class: "mono", text: e.secret }) : "",
        statusCell(e),
        fmtMs(e.latency_us / 1000) + (e.upstream_us ? ` (provider ${fmtMs(e.upstream_us / 1000)})` : ""),
      ]),
    );
    fill(
      body,
      kpis,
      d.truncated ? h("div", { class: "note", text: "Showing the most recent 200,000 events in this range." }) : null,
      h(
        "div",
        { class: "grid2" },
        panel("Requests over time", d.range === "24h" ? "per hour" : d.range === "7d" ? "per 6 hours" : "per day", timelineChart(d)),
        panel("Most-used secrets", "all access, including proxy calls", secretBars),
      ),
      panel("Machines", "every device that called the vault", machines),
      h(
        "div",
        { class: "grid2 even" },
        panel("Vault latency by operation", "time inside the vault, to first byte", table(latCols, lat(d.latency, true))),
        panel("Provider latency by secret", "proxy, verification and description calls", table([["Secret"], ...latCols.slice(1)], lat(d.upstream, true), "No provider calls in this range.")),
      ),
      panel("Recent activity", "latest 50 events", recent),
    );
  }

  // ---------------------------------------------------------------- station approvals

  // A spandeck station asked for a token. This page shows who is asking and
  // what the token would allow; approving needs a recent passphrase. When it
  // was opened as spandeck's pop-up it closes itself once nothing is left to
  // decide (browsers only let a script close a window a script opened, so in
  // an ordinary tab it simply says so instead).
  function approveView() {
    const box = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
    const handled = [];
    const finish = () => {
      const last = handled[handled.length - 1];
      fill(
        box,
        h("div", { class: "note" }, h("b", { text: last ? (last.approved ? "Approved." : "Denied.") : "Nothing is waiting for approval." }), " ", last && last.approved ? `${last.name} can collect its token now. You can close this window.` : "You can close this window."),
      );
      if (handled.length) setTimeout(() => window.close(), 600);
    };
    const load = async () => {
      let r;
      try {
        r = await api("GET", "/v1/token-requests");
      } catch (e) {
        return box.replaceChildren(errBox(e));
      }
      const items = r.requests.sort((a, b) => (a.id === S.approveId ? -1 : b.id === S.approveId ? 1 : 0));
      if (!items.length) return finish();
      fill(box, items.map((q) => requestCard(q)));
    };
    const requestCard = (q) => {
      const patterns = h("input", { class: "input mono", value: "*", "aria-label": "Keys it may use" });
      const getOnly = h("input", { type: "checkbox", checked: true });
      const err = h("p", { class: "form-error", role: "alert" });
      const who = q.tags && q.tags.length ? `tagged ${q.tags.join(", ")}` : q.user;
      const act = async (approve) => {
        err.textContent = "";
        try {
          if (approve) {
            const secrets = patterns.value.split(",").map((x) => x.trim()).filter(Boolean);
            const res = await api("POST", `/v1/token-requests/${q.id}/approve`, { secrets, proxy_get_only: getOnly.checked });
            handled.push({ approved: true, name: res.token_name });
          } else {
            await api("POST", `/v1/token-requests/${q.id}/deny`, {});
            handled.push({ approved: false, name: q.node });
          }
          load();
        } catch (e) {
          err.textContent = e.message;
        }
      };
      return h(
        "div",
        { class: "panel approve" + (q.id === S.approveId ? " focus" : "") },
        h("div", { class: "ph" }, h("h2", {}, "Machine ", h("span", { class: "mono", text: q.node })), h("p", { text: `asked ${ago(q.created_at)} · expires in ${Math.max(1, Math.ceil((q.expires_at - Date.now()) / 60000))} min` })),
        h("p", { class: "small" }, "Tailscale says this is ", h("b", { class: "mono", text: q.node_fqdn }), ` (${who}). It calls itself `, h("span", { class: "mono", text: q.label }), h("span", { class: "hint", text: " (reported by the machine, not checked)" }), "."),
        h("p", { class: "small", text: `If you approve, ${q.token_name} can list your keys and call providers through the vault with them, from this machine only. It can never read a raw value or see your owner-only keys.` }),
        field("ap-keys-" + q.id, "Keys it may use", patterns, "Comma-separated names; * is a wildcard, e.g. OPENAI_*, GITHUB_TOKEN."),
        h("label", { class: "check" }, getOnly, h("span", {}, h("b", { text: "Read-only (GET requests only)" }), " — ", h("span", { class: "hint", text: "Recommended. Untick to let it make changes at providers, as far as each key allows." }))),
        err,
        h("div", { class: "row-actions" }, h("button", { class: "btn primary", type: "button", text: "Approve", onclick: () => act(true) }), h("button", { class: "btn danger", type: "button", text: "Deny", onclick: () => act(false) })),
      );
    };
    load();
    return h("section", {}, head("Approve station access", "A spandeck station asked for a token. Approving needs your passphrase if you haven't entered it in the last 5 minutes."), box);
  }

  // ---------------------------------------------------------------- tokens

  const GET_ONLY_HINT =
    "Recommended for agents: it can read through the proxy but not change anything at the provider. Untick it to allow changes (e.g. pushing to GitHub), as far as the key itself allows.";

  // Change what an existing token may do. The token string stays the same, so
  // whatever uses it keeps working with the new permissions straight away.
  function tokenEditDialog(t, onDone) {
    const name = h("input", { class: "input", required: true, maxlength: 64, value: t.name });
    const checks = SCOPES.map(([k, label, hint]) => {
      const c = h("input", { type: "checkbox", value: k, checked: t.scopes.includes(k) });
      return [c, h("label", { class: "check" }, c, h("span", {}, h("b", { text: label }), " — ", h("span", { class: "hint", text: hint })))];
    });
    const getOnly = h("input", { type: "checkbox", checked: !!t.proxy_get_only });
    const globs = h("input", { class: "input mono", value: t.secrets.join(", "), placeholder: "*" });
    const nodes = h("input", { class: "input mono", value: t.nodes.join(", "), placeholder: "any machine" });
    const split = (v) => v.split(",").map((x) => x.trim()).filter(Boolean);
    openDialog(
      `Edit token "${t.name}"`,
      h(
        "div",
        {},
        h("p", { class: "small lead", text: "Changes apply on the token's next request. The token itself stays the same, so nothing needs setting up again." }),
        field("te-name", "Name", name),
        h("div", { class: "field" }, h("span", { class: "label", text: "Scopes" }), h("div", { class: "scopes" }, checks.map(([, l]) => l))),
        h("label", { class: "check" }, getOnly, h("span", {}, h("b", { text: "Proxy: GET requests only" }), " — ", h("span", { class: "hint", text: GET_ONLY_HINT }))),
        field("te-globs", "Secrets it may use", globs, "Comma-separated names; * is a wildcard."),
        field("te-nodes", "Only from these machines", nodes, "Leave empty for any machine on your tailnet."),
      ),
      "Save changes",
      async () => {
        const scopes = checks.filter(([c]) => c.checked).map(([c]) => c.value);
        await api("PATCH", `/v1/tokens/${t.id}`, { name: name.value.trim(), scopes, secrets: split(globs.value), nodes: split(nodes.value), proxy_get_only: getOnly.checked });
        toast(`Saved. "${name.value.trim()}" has its new permissions now.`);
        onDone();
      },
    );
  }

  function tokensView() {
    const out = h("div");
    const list = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
    const name = h("input", { class: "input", required: true, maxlength: 64, placeholder: "e.g. Claude Code on my laptop" });
    const checks = SCOPES.map(([k, label, hint]) => {
      const c = h("input", { type: "checkbox", value: k });
      return [c, h("label", { class: "check" }, c, h("span", {}, h("b", { text: label }), " — ", h("span", { class: "hint", text: hint })))];
    });
    const getOnly = h("input", { type: "checkbox", checked: true });
    const globs = h("input", { class: "input mono", value: "*", placeholder: "*" });
    const nodes = h("input", { class: "input mono", placeholder: "any machine" });
    const setScopes = (want) => checks.forEach(([c]) => (c.checked = want.includes(c.value)));
    setScopes(["list", "proxy"]);
    const err = h("p", { class: "form-error", role: "alert" });
    const form = h(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          const scopes = checks.filter(([c]) => c.checked).map(([c]) => c.value);
          const split = (v) => v.split(",").map((x) => x.trim()).filter(Boolean);
          try {
            const r = await api("POST", "/v1/tokens", { name: name.value.trim(), scopes, secrets: split(globs.value), nodes: split(nodes.value), proxy_get_only: getOnly.checked });
            out.replaceChildren(tokenOnce(r));
            name.value = "";
            loadTokens(list);
          } catch (ex) {
            err.textContent = ex.message;
          }
        },
      },
      h(
        "div",
        { class: "presets" },
        h("span", { class: "hint", text: "Presets:" }),
        h("button", { class: "btn", type: "button", onclick: () => setScopes(["list", "proxy"]), text: "Claude / agents (list + proxy)" }),
        h("button", { class: "btn", type: "button", onclick: () => setScopes(["read"]), text: "App that needs raw values (read)" }),
        h("button", { class: "btn", type: "button", onclick: () => setScopes(["list", "write"]), text: "Importer (list + write)" }),
      ),
      field("t-name", "Name", name),
      h("div", { class: "field" }, h("span", { class: "label", text: "Scopes" }), h("div", { class: "scopes" }, checks.map(([, l]) => l))),
      h("label", { class: "check" }, getOnly, h("span", {}, h("b", { text: "Proxy: GET requests only" }), " — ", h("span", { class: "hint", text: GET_ONLY_HINT }))),
      field("t-globs", "Secrets it may use", globs, "Comma-separated names; * is a wildcard, e.g. OPENAI_*, GITHUB_TOKEN."),
      field("t-nodes", "Only from these machines", nodes, "Optional comma-separated Tailscale machine names. A copied token is useless anywhere else."),
      err,
      h("button", { class: "btn primary", type: "submit", text: "Create token" }),
    );
    loadTokens(list);
    return h(
      "section",
      {},
      head("Tokens", "Give each app or agent its own token with only the scopes and secrets it needs. Requests must also come from a device on your tailnet."),
      out,
      panel("Existing tokens", null, list),
      panel("New token", null, form),
    );
  }

  function tokenOnce(r) {
    const origin = S.status.origin;
    const tok = r.token;
    // No command below contains the token: a token typed on a command line
    // ends up in shell history. Each one asks for it or reads $AGENTVAULT_TOKEN.
    const lines = [];
    if (r.scopes.includes("list") || r.scopes.includes("proxy")) {
      lines.push(["Claude Code (MCP and the agentvault skill): run this, then paste the token when it asks", "~/.claude/skills/agentvault/scripts/agentvault-cli setup"]);
    }
    const env = ["In scripts and apps, read the token from the environment, e.g. after: read -rs AGENTVAULT_TOKEN; export AGENTVAULT_TOKEN", null];
    if (r.scopes.includes("read")) lines.push(["Fetch a value", `curl -s -H "Authorization: Bearer $AGENTVAULT_TOKEN" \\\n  ${origin}/v1/secrets/NAME/value`]);
    if (r.scopes.includes("proxy")) lines.push(["Call a provider through the proxy", `curl -s -H "Authorization: Bearer $AGENTVAULT_TOKEN" \\\n  ${origin}/v1/proxy/OPENAI_API_KEY/v1/models`]);
    if (r.scopes.includes("list")) lines.push(["List secrets", `curl -s -H "Authorization: Bearer $AGENTVAULT_TOKEN" ${origin}/v1/secrets`]);
    if (lines.some(([, c]) => c.startsWith("curl"))) lines.splice(lines.findIndex(([, c]) => c.startsWith("curl")), 0, env);
    const copy = (text) => navigator.clipboard.writeText(text).then(() => toast("Copied."), () => toast("Couldn't copy", true));
    const copyToken = () =>
      copySecret(tok).then(() => toast(`Copied. It's cleared from the clipboard in ${CLIPBOARD_SECONDS} seconds.`), () => toast("Couldn't copy", true));
    return h(
      "div",
      { class: "secret-once", role: "status" },
      h("h3", { text: `Token "${r.name}" created. Copy it now: it won't be shown again.` }),
      h("pre", { text: tok }),
      h("div", { class: "row-actions" }, h("button", { class: "btn primary", type: "button", onclick: copyToken, text: "Copy token" })),
      lines.map(([label, cmd]) => (cmd ? [h("p", { class: "small", style: null, text: label }), h("pre", { text: cmd }), h("button", { class: "btn", type: "button", onclick: () => copy(cmd.replace(/\\\n\s*/g, "")), text: "Copy command" })] : h("p", { class: "hint", text: label }))),
    );
  }

  async function loadTokens(list) {
    try {
      const r = await api("GET", "/v1/tokens");
      const revoked = r.tokens.filter((t) => t.revoked_at).length;
      const clear = revoked
        ? h(
            "p",
            { class: "row-actions" },
            h("button", {
              class: "btn",
              text: `Remove ${revoked === 1 ? "the revoked token" : `all ${revoked} revoked tokens`}`,
              onclick: async () => {
                try {
                  const res = await api("POST", "/v1/tokens/remove-revoked", {});
                  toast(`Removed ${res.removed} revoked token${res.removed === 1 ? "" : "s"}.`);
                  loadTokens(list);
                } catch (e) {
                  toast(e.message, true);
                }
              },
            }),
          )
        : null;
      list.replaceChildren(
        clear || "",
        table(
          [["Name"], ["Scopes"], ["Secrets"], ["Machines"], ["Rotation"], ["Last used"], [""]],
          r.tokens.map((t) => [
            h("span", { title: "Created " + when(t.created_at), text: t.name }),
            t.scopes.join(", ") + (t.proxy_get_only && t.scopes.includes("proxy") ? " (GET only)" : ""),
            h("span", { class: "mono", text: t.secrets.join(", ") }),
            t.nodes.length ? h("span", { class: "mono", text: t.nodes.join(", ") }) : h("span", { class: "muted", text: "any" }),
            t.rotate_every_hours
              ? h("span", { title: t.last_rotated_at ? "Last rotated " + when(t.last_rotated_at) : "Not rotated yet", text: `every ${t.rotate_every_hours % 24 ? t.rotate_every_hours + " h" : t.rotate_every_hours / 24 + " d"}` + (t.name.startsWith("spandeck:") ? " (set in spandeck)" : "") })
              : h("span", { class: "muted", text: "never expires" }),
            t.revoked_at ? h("span", { class: "muted", text: "revoked " + ago(t.revoked_at) }) : h("span", { title: when(t.last_used_at), text: ago(t.last_used_at) }),
            t.revoked_at
              ? h("button", {
                  class: "btn",
                  title: "Take this revoked token off the list",
                  onclick: async () => {
                    try {
                      await api("POST", `/v1/tokens/${t.id}/remove`, {});
                      toast(`Removed ${t.name}.`);
                      loadTokens(list);
                    } catch (e) {
                      toast(e.message, true);
                    }
                  },
                  text: "Remove",
                })
              : h(
                  "div",
                  { class: "row-actions" },
                  h("button", { class: "btn", onclick: () => tokenEditDialog(t, () => loadTokens(list)), text: "Edit" }),
                  h("button", {
                  class: "btn danger",
                  onclick: async () => {
                    if (!confirm(`Revoke "${t.name}"? Anything using it stops working immediately.`)) return;
                    try {
                      await api("DELETE", `/v1/tokens/${t.id}`);
                      toast(`Revoked ${t.name}.`);
                      loadTokens(list);
                    } catch (e) {
                      toast(e.message, true);
                    }
                  },
                  text: "Revoke",
                }),
                ),
          ]),
          "No tokens yet.",
        ),
      );
    } catch (e) {
      list.replaceChildren(errBox(e));
    }
  }

  // ---------------------------------------------------------------- settings

  function settingsView() {
    const d = S.status.describer;
    const cur = h("input", { class: "input", type: "password", autocomplete: "current-password", required: true });
    const n1 = h("input", { class: "input", type: "password", autocomplete: "new-password", minlength: 12, required: true });
    const n2 = h("input", { class: "input", type: "password", autocomplete: "new-password", minlength: 12, required: true });
    const perr = h("p", { class: "form-error", role: "alert" });
    const pass = h(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          perr.textContent = "";
          if (n1.value !== n2.value) return (perr.textContent = "The new passphrases don't match.");
          try {
            const r = await api("POST", "/v1/passphrase", { current: cur.value, new: n1.value });
            cur.value = n1.value = n2.value = "";
            if (r.auto_unlock_stale) {
              S.status.auto_unlock = "stale";
              toast("Passphrase changed. Automatic unlock still has the old one: run " + AUTO_UNLOCK_CMD + " on the vault machine.", true);
              render(shell());
            } else toast("Passphrase changed.");
          } catch (ex) {
            perr.textContent = ex.message;
          }
        },
      },
      field("s-cur", "Current passphrase", cur),
      field("s-n1", "New passphrase", n1, "At least 12 characters."),
      field("s-n2", "New passphrase again", n2),
      perr,
      h("button", { class: "btn primary", type: "submit", text: "Change passphrase" }),
    );
    const audit = h("p", { class: "small muted", text: "Every request is logged with a hash chain, so edits or deletions in the middle of the log are detectable." });
    const auditBtn = h("button", {
      class: "btn",
      text: "Verify the log now",
      onclick: async () => {
        try {
          const r = await api("GET", "/v1/audit/verify");
          fill(
            audit,
            h("span", { class: "status " + (r.ok ? "good" : "crit") }, h("span", { class: "dot" }), r.ok ? `Intact: ${num(r.checked)} events checked.` : `Broken at event #${r.first_bad_id}. The log was altered.`),
            r.head ? h("div", { class: "hint mono", text: "Head: " + r.head }) : null,
          );
        } catch (e) {
          toast(e.message, true);
        }
      },
    });
    const o = S.status.origin;
    const ref = [
      ["GET", "/v1/secrets", "list names and descriptions"],
      ["POST", "/v1/secrets", "add: {name, value, notes, tags}"],
      ["GET", "/v1/secrets/NAME", "one secret's metadata"],
      ["PATCH", "/v1/secrets/NAME", "rename, new value, notes, tags"],
      ["DELETE", "/v1/secrets/NAME", "delete"],
      ["GET", "/v1/secrets/NAME/value", "raw value (read scope)"],
      ["ANY", "/v1/proxy/NAME/PATH", "call the provider with the key attached"],
      ["POST", "/v1/secrets/NAME/rotate", "rotate: {} for automatic, {value} for by hand (owner)"],
      ["GET", "/v1/rotations", "recent rotations (owner)"],
      ["GET", "/v1/attention", "what needs attention (owner)"],
      ["POST", "/v1/import/preview", "parse a key file: {text} (owner)"],
      ["POST", "/mcp", "MCP endpoint for Claude"],
    ];
    return h(
      "section",
      {},
      head("Settings"),
      h(
        "div",
        { class: "grid2 even" },
        panel(
          "Vault",
          null,
          h(
            "div",
            {},
            h("p", { class: "small", text: "Locking wipes the encryption key from memory. Nothing can be decrypted, by you or any token, until you sign in again." }),
            h(
              "p",
              { class: "small" },
              "Unlock after a restart: ",
              {
                on: h("span", { class: "status good" }, h("span", { class: "dot" }), "automatic"),
                failed: h("span", { class: "status crit" }, h("span", { class: "dot" }), "automatic, but it failed at the last start"),
                stale: h("span", { class: "status warn" }, h("span", { class: "dot" }), "automatic, but it has your old passphrase"),
              }[S.status.auto_unlock] || h("span", { class: "status warn" }, h("span", { class: "dot" }), "by hand (sign in after each restart)"),
            ),
            S.status.auto_unlock === "on" ? null : h("p", { class: "hint" }, ["failed", "stale"].includes(S.status.auto_unlock) ? "To fix it, run " : "To make it automatic, run ", h("code", { text: AUTO_UNLOCK_CMD }), " on the vault machine."),
            h("p", { style: null }, h("button", { class: "btn danger", onclick: lockVault, text: "Lock vault now" })),
          ),
        ),
        panel(
          "Descriptions",
          null,
          h(
            "div",
            { class: "small" },
            h("p", {}, "Claude: ", d.claude_ready ? h("span", { class: "status good" }, h("span", { class: "dot" }), `on (${d.model}, using ${d.claude_secret})`) : h("span", { class: "status warn" }, h("span", { class: "dot" }), `off: ${d.claude_problem}`)),
            d.claude_ready && d.built_in_descriptions
              ? h(
                  "p",
                  {},
                  h("button", {
                    class: "btn",
                    text: `Describe ${d.built_in_descriptions === 1 ? "1 key" : `${d.built_in_descriptions} keys`} with Claude`,
                    title: "Keys added while Claude was off still have built-in descriptions",
                    onclick: async (e) => {
                      e.target.disabled = true;
                      try {
                        const r = await api("POST", "/v1/describe-all", {});
                        toast(`Claude is describing ${r.describing} key${r.describing === 1 ? "" : "s"}. They update on the Secrets page as each finishes.`);
                        d.built_in_descriptions = 0;
                        e.target.remove();
                      } catch (err) {
                        e.target.disabled = false;
                        toast(err.message, true);
                      }
                    },
                  }),
                  h("span", { class: "muted", text: " built-in descriptions, from before Claude was on" }),
                )
              : null,
            h("p", {}, "Provider checks: ", d.verify_with_provider ? "on, when a key is added or changed and again every week, so keys that stop working show under Needs attention" : "off"),
            h("p", {}, "Scheduled rotation: ", (S.status.rotation || {}).scheduled ? "on" : "off", ` · old keys revoked ${(S.status.rotation || {}).grace_hours || 24} hours after rotating`),
            h("p", { class: "muted", text: "Claude only ever receives a key's name, your notes, the detected provider and what the provider reported about the key: never the value." }),
          ),
        ),
      ),
      h("div", { class: "grid2 even" }, panel("Change passphrase", null, pass), panel("Audit log", null, h("div", {}, audit, h("p", {}, auditBtn)))),
      panel(
        "API",
        `Base URL ${o}. Send Authorization: Bearer <token>.`,
        table(
          [["Method"], ["Path"], ["What it does"]],
          ref.map(([m, p, w]) => [h("span", { class: "mono", text: m }), h("span", { class: "mono", text: p }), w]),
          "",
        ),
      ),
    );
  }

  boot();
})();
