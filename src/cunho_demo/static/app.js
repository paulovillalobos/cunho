// The demo page: create an offer, show its QR code, and follow the issuance through the demo service's API. The
// same page, opened at /o/<offer reference> (the QR code a phone's camera reads), is the phone page: it shows that
// one offer, opens it in a wallet app on the phone, or hands it to the demo wallet.
"use strict";

(function () {
  const ORDER = ["waiting", "signing_in", "connected", "issued", "stored"];
  // Where each step the API reports sits in the list, and how it reads.
  const PLACE = {
    waiting: ["waiting", ""],
    signing_in: ["signing_in", ""],
    connected: ["connected", ""],
    held: ["connected", ""],
    released: ["connected", ""],
    refused: ["issued", "bad"],
    rejected: ["issued", "bad"],
    token_rejected: ["connected", "bad"], // refused before it got a token: the wallet never connected
    issued: ["issued", "good"], // issued is done: a wallet need not report that it stored it (OpenID4VCI 1.0 §11)
    stored: ["stored", "good"],
    failed: ["stored", "bad"],
    deleted: ["stored", "bad"],
    revoked: ["stored", "bad"],
    cancelled: ["signing_in", "bad"],
    closed: ["waiting", "bad"],
    expired: ["waiting", "bad"],
  };
  const FINAL = new Set(["stored", "refused", "failed", "deleted", "revoked", "closed", "expired", "cancelled"]);
  // What the demo wallet did, as the page says it, and why it stopped when it did.
  const WALLET_STEPS = {
    wallet_metadata: () => t("did_metadata"),
    wallet_pin: () => t("did_pin"),
    wallet_token: () => t("did_token"),
    wallet_proof: () => t("did_proof"),
    wallet_issued: () => t("did_issued"),
    wallet_stored: () => t("did_stored"),
  };
  const WALLET_ERRORS = {
    wallet_token: () => t("werr_token"),
    wallet_refused: () => t("werr_refused"),
    wallet_no_pin: () => t("werr_no_pin"),
    wallet_unreachable: () => t("werr_broken"),
    wallet_metadata: () => t("werr_broken"),
    wallet_notification: () => t("werr_broken"),
    wallet_broken: () => t("werr_broken"),
  };
  // Why the issuer refused a real wallet's credential request, in words, by the rule cunho names.
  const WHY = {
    "KA.BIND_TO_ATTESTED_KEY": "why_same_key",
    "VCI.F1.PROOF_ISS_ANON_PREAUTH": "why_iss",
    "VCI.NONCE.C_NONCE_VALID": "why_nonce",
    "VCI.F1.PROOF_AUD": "why_aud",
    "VCI.F1.PROOF_IAT": "why_iat",
    "VCI.F1.PROOF_TYP": "why_typ",
    "VCI.F4.PROOF_SIGNATURE": "why_signature",
    "KA.VERIFY": "why_attestation",
    "OAUTH.DPOP_REQUIRED": "why_dpop",
  };
  const LIST_STATUS = {
    valid: () => t("list_valid"),
    invalid: () => t("list_invalid"),
    suspended: () => t("list_suspended"),
    unknown: () => t("list_unknown"),
    none: () => t("list_none"),
  };

  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const joined = location.pathname.match(/^\/o\/([A-Za-z0-9_-]{8,64})$/); // the phone page, by offer reference
  let lang = params.get("lang") === "pt" || params.get("lang") === "en"
    ? params.get("lang")
    : (navigator.language || "en").toLowerCase().startsWith("pt") ? "pt" : "en";
  let session = null;
  let lastStep = null;
  let lastView = null;
  let pollTimer = null;
  let pollDelay = 1000;
  let expiresAt = 0;
  let expiryTimer = null;
  let simple = true; // Simple shows the story; Advanced every option and every check
  let declined = false; // the phone page's visitor declined the offer, as a wallet lets them

  // The visitor's choice of view, kept in this browser only; the page works the same without storage.
  function storedMode() {
    try {
      return localStorage.getItem("cunho-demo-mode");
    } catch (error) {
      return null;
    }
  }

  function setMode(value) {
    simple = value !== "advanced";
    document.body.classList.toggle("simple", simple);
    for (const input of document.querySelectorAll('input[name="mode"]')) input.checked = input.value === value;
    try {
      localStorage.setItem("cunho-demo-mode", simple ? "simple" : "advanced");
    } catch (error) {
      // a private window or blocked storage: the choice lasts until the page is closed
    }
    syncScan();
    syncOptions();
    if (lastView) renderWallet(lastView);
  }

  function t(key, values) {
    let text = (window.I18N[lang] && window.I18N[lang][key]) || window.I18N.en[key] || key;
    for (const [name, value] of Object.entries(values || {})) text = text.replace(`{${name}}`, value);
    return text;
  }

  // A claim's label: the page's word for it when it has one, else the claim's own name.
  function label(name) {
    const key = `claim_${name}`;
    return (window.I18N[lang] && window.I18N[lang][key]) || window.I18N.en[key] || name;
  }

  // Where this page's session is on the API: by its id, or on the phone page by the offer's reference.
  function base() {
    if (joined) return `/api/offers/${encodeURIComponent(joined[1])}`;
    return `/api/sessions/${encodeURIComponent(session.id)}`;
  }

  function translate() {
    document.documentElement.lang = lang;
    document.title = t("doc_title");
    for (const node of document.querySelectorAll("[data-i18n]")) node.textContent = t(node.dataset.i18n);
    const other = lang === "pt" ? "en" : "pt";
    $("language").lang = other;
    $("qr").setAttribute("aria-label", t("qr_label"));
    document.querySelector(".mode").setAttribute("aria-label", t("mode_label"));
    if (joined) {
      document.querySelector("h1").textContent = t("phone_title");
      document.querySelector(".lead").textContent = t("phone_lead");
    }
    syncOptions();
    syncScan();
    if (session) renderCard(session);
    if (lastStep) render(lastStep);
    if (lastView) renderWallet(lastView);
    updateExpiry();
  }

  function choice(name) {
    const checked = document.querySelector(`input[name="${name}"]:checked`);
    return checked ? checked.value : null;
  }

  function syncOptions() {
    const course = choice("credential") === "course";
    const code = choice("flow") === "authorization_code";
    $("format-options").hidden = !course;
    $("pin-option").hidden = code;
    $("fields-pid").hidden = course;
    $("fields-course").hidden = !course;
    $("flow-hint").textContent = code ? t("flow_code_hint") : t("flow_pre_hint");
    $("cred-desc").textContent = t(`desc_${course ? "course" : "pid"}${simple ? "" : "_advanced"}`);
    if (!session) renderMain();
  }

  // Two QR codes of the one offer: the phone camera's opens the phone page, the wallet app's is the offer itself.
  function syncScan() {
    const camera = choice("scan") !== "wallet"; // the code a phone's camera reads, unless the wallet app's is asked for
    $("scan-hint").textContent = camera ? t("scan_camera_hint") : t("scan_wallet_hint");
    if (session && session.qr_svg) {
      // made by the demo service (segno), never from anything a visitor typed
      $("qr").innerHTML = camera ? session.qr_svg_phone : session.qr_svg;
    }
  }

  // While an offer is open its choices stay in view; changing one leaves that offer and makes ready for a new one.
  function lock(locked) {
    $("choose").classList.toggle("locked", locked);
    $("start").hidden = locked;
    $("idle").hidden = locked;
    $("issue").hidden = !locked;
  }

  // The credential as the wallet will hold it: its card, and the fields on its face, of the person it is for.
  function renderCard(view) {
    const course = view.credential === "course";
    const card = $("mini-card");
    card.classList.toggle("pid", !course);
    card.classList.toggle("course", course);
    $("mini-kind").textContent = course ? t("course_kind") : t("pid_kind");
    $("mini-name").textContent = course ? t("course_title") : "PID";
    $("persona-name").textContent = view.persona.name;
    fill($("face"), view.card || []);

  }

  // Rows of a definition list, every value set as text, never as markup.
  function fill(list, rows) {
    list.textContent = "";
    for (const [name, value] of rows) {
      const row = document.createElement("div");
      const term = document.createElement("dt");
      const detail = document.createElement("dd");
      term.textContent = label(name);
      detail.textContent = value;
      row.append(term, detail);
      list.append(row);
    }
  }

  async function call(method, path, body) {
    const init = { method, headers: { Accept: "application/json" }, cache: "no-store" };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetch(path, init);
    } catch (error) {
      throw new Error(t("error_network"));
    }
    let answer = {};
    try {
      answer = await response.json();
    } catch (error) {
      answer = {};
    }
    if (!response.ok) {
      const failure = new Error(answer.message || t("error_generic"));
      failure.status = response.status;
      failure.code = answer.error;
      throw failure;
    }
    return answer;
  }

  function showError(id, message) {
    const box = $(id);
    box.textContent = message || "";
    box.hidden = !message;
    if (joined && id === "issue-error") showPhoneError(message);
  }

  // On the phone page, before there is an offer to draw (an ended reference), the error still shows.
  function showPhoneError(message) {
    $("wallet-screen").hidden = false;
    if (session) {
      renderPhone();
      return;
    }
    $("w-error").textContent = message || "";
    $("w-error").hidden = !message;
    for (const id of ["w-card", "w-info", "w-history-box", "w-actions", "open-wallet-phone"]) $(id).hidden = Boolean(message);
  }

  // "Try it now" makes the offer and turns the card over to its QR code; the demo wallet waits to be asked.
  async function start() {
    const button = $("start");
    if (button.disabled) return; // one offer at a time
    showError("start-error", "");
    button.setAttribute("aria-busy", "true");
    button.disabled = true;
    const body = { credential: choice("credential") };
    if (!simple) {
      // Simple takes the defaults: straight away, no PIN, the course certificate as SD-JWT VC.
      body.flow = choice("flow");
      if (body.credential === "course") body.format = choice("format");
      if (body.flow === "pre-authorized_code") body.pin = document.querySelector('input[name="pin"]').checked;
    }
    try {
      session = await call("POST", "/api/sessions", body);
    } catch (error) {
      showError("start-error", error.message);
      return;
    } finally {
      button.removeAttribute("aria-busy");
      button.disabled = false;
    }
    opened();
    $("pin").hidden = !session.tx_code;
    $("pin-value").textContent = session.tx_code || "";
    $("phone-here").href = session.phone_path;
    syncScan();
    expiresAt = Date.now() + session.expires_in * 1000;
    clearInterval(expiryTimer);
    expiryTimer = setInterval(updateExpiry, 15000);
    updateExpiry();
    lock(true);
    $("offer").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "nearest" });
    $("issue-title").focus({ preventScroll: true });
    lastStep = null;
    render("waiting");
    pollDelay = 1000;
    schedule();
  }

  // What both pages show once they have an offer: its wallet link, its card, and whether the demo wallet can take it.
  function opened() {
    $("open-wallet").href = session.wallet_link;
    $("open-wallet-phone").href = session.wallet_link;
    $("w-open").href = session.wallet_link;
    renderCard(session);
    $("steps").classList.toggle("code", session.flow === "authorization_code");
    $("demo-wallet-box").hidden = !session.demo_wallet;
    $("demo-wallet-code").hidden = session.demo_wallet || session.flow !== "authorization_code";
    showError("issue-error", "");
    renderWallet(session);
  }

  function updateExpiry() {
    const box = $("expiry");
    if (!session || !expiresAt || (lastStep && lastStep !== "waiting" && lastStep !== "signing_in")) {
      box.textContent = "";
      return;
    }
    const minutes = Math.floor((expiresAt - Date.now()) / 60000);
    box.textContent = minutes >= 1 ? t("expires_in", { minutes }) : t("expires_soon");
  }

  function schedule() {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(poll, pollDelay);
  }

  async function poll() {
    if (!session) return;
    const asked = session;
    try {
      const view = await call("GET", base());
      if (session !== asked) return; // an answer about a session the visitor has left
      session.persona = view.persona; // a code-flow login may pick another person than the one first shown
      session.card = view.card;
      renderCard(session);
      renderWallet(view);
      const running = view.wallet && view.wallet.state === "running";
      if (view.step !== lastStep || running) pollDelay = 1000; else pollDelay = Math.min(pollDelay * 1.5, 3000);
      render(view.step);
      showError("issue-error", "");
      if (FINAL.has(view.step) && view.step !== "stored" && !running) return;
      if (view.step === "stored" && !running) pollDelay = 10000; // a wallet may still report a deletion
    } catch (error) {
      if (session !== asked) return;
      if (error.status === 404) {
        render("expired");
        return;
      }
      showError("issue-error", error.message);
      pollDelay = Math.min(pollDelay * 2, 15000);
    }
    schedule();
  }

  function render(step) {
    lastStep = step;
    const [place, tone] = PLACE[step] || PLACE.waiting;
    const index = ORDER.indexOf(place);
    for (const item of $("steps").children) {
      const at = ORDER.indexOf(item.dataset.step);
      const words = item.querySelector("[data-i18n]");
      // A step that went wrong says what happened instead of what was hoped for.
      const key = words.dataset.i18n;
      const word = key === "step_stored" && demoDone() ? "step_stored_demo" : key;
      words.textContent = at === index && tone === "bad" ? t(`ended_${step}`) : t(word);
      item.classList.toggle("done", at < index || (at === index && tone === "good"));
      item.classList.toggle("current", at === index && tone === "");
      item.classList.toggle("failed", at === index && tone === "bad");
      if (at === index) item.setAttribute("aria-current", "step"); else item.removeAttribute("aria-current");
    }
    const status = $("status");
    const done = step === "stored" && demoDone() && !joined;
    status.textContent = done
      ? t("status_stored_demo", { name: session.persona.name })
      : step === "rejected" || step === "token_rejected"
        ? refusalText()
        : t(`status_${step}`);
    status.className = `status ${tone}`;
    // Stored by the demo wallet, it says where the credential is: not in an app on the visitor's phone.
    $("stored-note").hidden = !done;
    $("issue").classList.toggle("demo-done", done);
    // The phone page reads the offer by its reference, which cannot decide or revoke; the page that made it can.
    $("review").hidden = joined || step !== "held";
    $("revoke-box").hidden = joined || !["issued", "stored", "failed", "deleted"].includes(step);
    $("revoke-elsewhere").hidden = !joined || !["issued", "stored"].includes(step);
    const scanning = step === "waiting" || step === "signing_in";
    const title = joined ? t("phone_issue_title") : t("issue_title");
    $("issue-title").querySelector("[data-i18n]").textContent = scanning ? title : t("issue_title_after");
    $("issue").classList.toggle("after", !scanning);
    $("issue").classList.toggle("stored", step === "stored");
    // A wallet app that was issued the credential and does not report storing it ends at "Credential signed": the
    // last dot, which only a report could fill, is not shown as if something were missing.
    const real = !(lastView && lastView.wallet);
    $("steps").classList.toggle("ends-issued", real && step === "issued");
    renderPhone();
    renderMain();
    updateExpiry();
  }

  // What the issuer said when it refused the wallet's last credential request: in words, and in Advanced its code
  // and rule as cunho names them (set as text, never as markup).
  function refusalText() {
    const refusal = lastView && lastView.refusal;
    if (!refusal) return t("status_rejected_unknown");
    const why = WHY[refusal.rule] ? t(WHY[refusal.rule]) : t("why_other", { error: refusal.error });
    return t("status_rejected", { why }) + (simple ? "" : ` (${refusal.error}, ${refusal.rule})`);
  }

  // Whether the demo wallet has taken the credential (a real wallet app's issuance has no run).
  function demoDone() {
    return Boolean(lastView && lastView.wallet && lastView.wallet.state === "done" && lastView.wallet.credentials.length);
  }

  // The demo wallet's run: what it did, how it ended, and what it holds.
  // The phone page, drawn as a wallet: the card, what it holds (Info), what happened to it (History), and the
  // person's yes or no before anything is stored. With no demo wallet for the offer, the real wallet's link leads.
  const happened = []; // the phone page's History (not window.history, which the language switch uses)
  const logged = new Set();
  let lastChecked = null;
  let toastTimer = null;

  function remember(key, text) {
    if (key && logged.has(key)) return;
    if (key) logged.add(key);
    const now = new Date();
    happened.push([text, `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`]);
  }

  function toast(text) {
    $("w-toast-text").textContent = text;
    $("w-toast").hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      $("w-toast").hidden = true;
    }, 3200);
  }

  function rowsInto(list, groups) {
    list.textContent = "";
    for (const rows of groups) {
      rows.forEach(([term, value], at) => {
        if (value === undefined || value === null || value === "") return;
        const row = document.createElement("div");
        if (at === 0 && list.children.length) row.className = "first-of-group";
        const dt = document.createElement("dt");
        const dd = document.createElement("dd");
        dt.textContent = term;
        dd.textContent = value;
        row.append(dt, dd);
        list.append(row);
      });
    }
  }

  // The credential's card (card.js), on both pages: what the offer says until the credential is stored, then what the
  // wallet holds (or, taken by a real wallet app, that the app has it). Before there is an offer, the main page's card
  // shows the credential chosen. Its chart lines draw out once the demo wallet has found the credential genuine, and
  // go if it is revoked.
  function cardFace(view) {
    const course = view ? view.credential === "course" : choice("credential") === "course";
    const run = view && view.wallet;
    const stored = Boolean(run) && run.state === "done" && run.credentials.length > 0;
    // A real wallet app took it: the issuer issued it to the app (most apps never report that they stored it).
    const elsewhere = Boolean(view) && !run && (lastStep === "issued" || lastStep === "stored");
    const genuine = stored && run.credentials.every((c) => c.signature && c.digests && c.holder_bound);
    const fields = Object.fromEntries((view && view.card) || []);
    const holder = (view && view.persona && view.persona.name) || t("card_preview_name");
    const until = stored ? (run.credentials[0].valid_until || "").slice(0, 10) : "";
    const date = until
      ? new Date(`${until}T00:00:00Z`).toLocaleDateString(lang === "pt" ? "pt-PT" : "en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" })
      : "";
    const pending = elsewhere ? t("card_in_wallet_app") : t("card_not_added");
    const face = course
      ? {
          kind: "course", issuer: "FOAAP", issuerNote: t("card_academy"), type: t("course_title"),
          typeNote: view ? t("card_credits", { ects: fields.ects_credits || "", level: fields.level_of_learning_experience || "" }) : "",
          name: holder, line: fields.achievement_title || pending, corner: fields.assessment_grade || t("card_demo_corner_course"),
        }
      : {
          kind: "pid", issuer: "FOAAP", issuerNote: t("card_demo_issuer"), type: t("card_pid"), typeNote: t("card_country"),
          name: holder, line: date ? t("card_valid_until", { date }) : pending, corner: t("card_demo_corner"),
        };
    // The card lights up once the demo wallet found the credential genuine, or once a wallet app was issued it.
    const shines = (stored && genuine && statusOf(run) !== "invalid") || elsewhere;
    return { face, verified: shines && lastStep !== "revoked" };
  }

  // A polled or acted-on view says where the issuance is, not what was offered: the offer's own fields come from it.
  function withOffer(view) {
    return { ...session, ...(view || {}), credential: session.credential, format: session.format };
  }

  let phoneCard = null;
  function renderPhoneCard(view) {
    if (!phoneCard) phoneCard = window.CunhoCard.create($("w-card"));
    const { face, verified } = cardFace(withOffer(view));
    phoneCard.show(face);
    phoneCard.verified(verified);
  }

  // The main page's card: the credential chosen, then the offer's. It turns over to its QR code while the offer
  // waits for a wallet, and back once a wallet has taken it.
  let mainCard = null;
  function renderMain() {
    if (joined || !window.CunhoCard) return;
    if (!mainCard) mainCard = window.CunhoCard.create($("m-card"));
    const { face, verified } = cardFace(session ? withOffer(lastView) : null);
    mainCard.show(face);
    mainCard.verified(verified);
    const scanning = Boolean(session) && (!lastStep || lastStep === "waiting" || lastStep === "signing_in");
    $("stage").classList.toggle("flipped", scanning);
    $("card-front").setAttribute("aria-hidden", String(scanning));
    $("card-back").setAttribute("aria-hidden", String(!scanning));
    $("card-back").inert = !scanning;
  }

  function renderPhone() {
    if (!joined || !session) return;
    const view = lastView || session;
    const run = view.wallet;
    const course = session.credential === "course";
    const demo = Boolean(session.demo_wallet);
    const taken = Boolean(run) && !run.retry;
    const waiting = !lastStep || lastStep === "waiting";
    const offering = demo && !taken && waiting;
    const stored = Boolean(run) && run.state === "done" && run.credentials.length > 0;
    const elsewhere = !run && (lastStep === "issued" || lastStep === "stored"); // a real wallet app was issued it
    const issuer = t("brand");
    $("wallet-screen").hidden = false;

    if (stored && !logged.has("added")) toast(t("w_toast_added"));
    if (stored) remember("added", t("w_h_added"));
    if (lastStep === "revoked") remember("revoked", t("w_h_revoked"));
    if (elsewhere) remember("elsewhere", t("w_h_elsewhere"));
    if (run && run.checked_at && run.checked_at !== lastChecked) {
      lastChecked = run.checked_at;
      const worst = statusOf(run);
      remember(null, t("w_h_checked", { status: (LIST_STATUS[worst] || LIST_STATUS.unknown)() }));
    }

    $("w-title").textContent = stored
      ? t("result_title_wallet")
      : elsewhere
        ? t("w_elsewhere_title")
      : offering && declined
        ? t("w_declined_title")
        : t("w_offer_title");
    const from = $("w-from");
    from.textContent = "";
    const strong = document.createElement("strong");
    strong.textContent = issuer;
    if (offering && declined) {
      from.textContent = t("consent_declined");
    } else if (stored || elsewhere) {
      from.append(t("w_issued_by"), " ", strong);
    } else {
      from.append(strong, " ", t("consent_wants"));
    }

    const meta = [
      [t("w_credential"), course ? t("course_title") : t("pid_title")],
      [t("w_issuer"), issuer],
    ];
    let person = (view.card || session.card || []).map(([name, value]) => [label(name), value]);
    if (stored) {
      const claims = {};
      for (const credential of run.credentials) {
        for (const [name, value] of credential.claims) if (!(name in claims)) claims[name] = value;
      }
      meta.push([t("w_issued_on"), claims.date_of_issuance || claims.issuance_date || claims.issue_date]);
      meta.push([t("valid_until"), (run.credentials[0].valid_until || "").slice(0, 10)]);
      const born = claims.birthdate || claims.birth_date;
      const years = age(born);
      person = course
        ? [
            [label("given_name"), claims.given_name],
            [label("family_name"), claims.family_name],
            [label("achievement_title"), claims.achievement_title],
            [label("assessment_grade"), claims.assessment_grade],
            [label("ects_credits"), claims.ects_credits],
            [label("course_provider"), claims.course_provider],
          ]
        : [
            [label("given_name"), claims.given_name],
            [label("family_name"), claims.family_name],
            [label("birthdate"), born],
            [t("r_age"), years === null ? "" : t("years", { n: years })],
            [label("place_of_birth"), claims.place_of_birth],
            [label("nationalities"), claims.nationalities || claims.nationality],
          ];
    }
    rowsInto($("w-info-rows"), [meta, person]);

    const list = $("w-history");
    list.textContent = "";
    for (const [text, time] of [...happened].reverse()) {
      const item = document.createElement("li");
      const what = document.createElement("span");
      const when = document.createElement("time");
      what.textContent = text;
      when.textContent = time;
      item.append(what, when);
      list.append(item);
    }

    $("w-status-row").hidden = !stored;
    if (stored) {
      const worst = run.checked_at ? statusOf(run) : null;
      const pill = $("w-status");
      pill.hidden = !worst;
      if (worst) {
        pill.className = `list-status ${worst}`;
        pill.textContent = (LIST_STATUS[worst] || LIST_STATUS.unknown)();
      }
    }
    const genuine = stored && run.credentials.every((c) => c.signature && c.digests && c.holder_bound);
    renderPhoneCard(view);
    $("w-check").hidden = !stored;
    $("w-check").className = `w-check ${genuine ? "" : "bad"}`;
    $("w-check").textContent = stored ? t(genuine ? "r_genuine" : "r_not_genuine") : "";

    const running = Boolean(run) && run.state === "running";
    const external = !run && !waiting && !FINAL.has(lastStep);
    $("w-busy").hidden = !(running || external);
    $("w-busy-text").textContent = running ? t("w_adding") : external ? t(`status_${lastStep}`) : "";
    // A request that failed (an offer that ended, a PIN left empty, a status the issuer could not give) says so.
    const asked = $("issue-error").hidden ? "" : $("issue-error").textContent;
    $("w-error").hidden = !(run && run.state === "failed");
    $("w-error").textContent = run && run.state === "failed" ? (WALLET_ERRORS[run.error] || WALLET_ERRORS.wallet_broken)() : "";
    if (!run && FINAL.has(lastStep) && lastStep !== "stored") {
      $("w-error").hidden = false;
      $("w-error").textContent = t(`status_${lastStep}`);
    }
    if (asked) {
      $("w-error").hidden = false;
      $("w-error").textContent = asked;
    }
    $("demo-pin").hidden = !(offering && !declined && view.pin);
    $("w-actions").hidden = !(offering && !declined);
    $("w-again").hidden = !(offering && declined);
    $("w-open").hidden = !(!demo && waiting);
    $("open-wallet-phone").hidden = !(offering && !declined);
  }

  function statusOf(run) {
    const statuses = run.credentials.map((c) => c.status_value).filter(Boolean);
    if (statuses.includes("invalid")) return "invalid";
    return statuses.length && statuses.every((v) => v === "valid") ? "valid" : "unknown";
  }

  // Years from a birth date (YYYY-MM-DD) to today.
  function age(birthdate) {
    const born = /^(\d{4})-(\d{2})-(\d{2})$/.exec(birthdate || "");
    if (!born) return null;
    const now = new Date();
    let years = now.getFullYear() - Number(born[1]);
    const month = now.getMonth() + 1;
    if (month < Number(born[2]) || (month === Number(born[2]) && now.getDate() < Number(born[3]))) years -= 1;
    return years;
  }

  // What the wallet received, as anyone would read it: who, how old, from where, and who issued it.
  function renderResult(run) {
    const box = $("result");
    box.hidden = run.credentials.length === 0;
    if (box.hidden) return;
    $("result-title").textContent = joined ? t("result_title_wallet") : t("result_title");
    const claims = {};
    for (const credential of run.credentials) {
      for (const [name, value] of credential.claims) if (!(name in claims)) claims[name] = value;
    }
    const name = [claims.given_name, claims.family_name].filter(Boolean).join(" ");
    const born = claims.birthdate || claims.birth_date;
    const years = age(born);
    const rows = [[t("r_name"), name]];
    if (claims.achievement_title) {
      rows.push([t("r_course"), claims.achievement_title]);
      if (claims.assessment_grade) rows.push([t("r_grade"), claims.assessment_grade]);
      rows.push([t("r_issuer"), claims.course_provider || run.credentials[0].signer || ""]);
    } else {
      if (years !== null) rows.push([t("r_age"), t("years", { n: years })]);
      if (claims.place_of_birth) rows.push([t("r_place"), claims.place_of_birth]);
      rows.push([t("r_issuer"), claims.issuing_authority || run.credentials[0].signer || ""]);
    }
    const list = $("result-rows");
    list.textContent = "";
    for (const [term, value] of rows) {
      const row = document.createElement("div");
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = term;
      dd.textContent = value;
      row.append(dt, dd);
      list.append(row);
    }
    const genuine = run.credentials.every((c) => c.signature && c.digests && c.holder_bound);
    const check = $("result-check");
    check.className = `result-check ${genuine ? "ok" : "bad"}`;
    check.textContent = genuine ? t("r_genuine") : t("r_not_genuine");
    const statuses = run.credentials.map((c) => c.status_value).filter(Boolean);
    const status = $("result-status");
    status.hidden = statuses.length === 0;
    if (statuses.length) {
      const worst = statuses.includes("invalid") ? "invalid" : statuses.every((v) => v === "valid") ? "valid" : "unknown";
      status.className = `list-status ${worst}`;
      status.textContent = (LIST_STATUS[worst] || LIST_STATUS.unknown)();
    }
  }

  function renderWallet(view) {
    lastView = view;
    const run = view.wallet;
    const started = Boolean(run);
    const taken = started && !run.retry; // a failed run is tried again only if it never redeemed the offer
    // The phone page asks first, as a wallet does; the page that made the offer has a plain button.
    $("demo-wallet-box").hidden = joined || !session || !session.demo_wallet || taken;
    $("wallet-box").hidden = !started;
    if (!started) {
      renderPhone();
      renderMain();
      $("inside").hidden = true;
      $("result").hidden = true;
      $("wallet-error").hidden = true;
      $("result-error").hidden = true; // an error of an offer the visitor left is not this one's (the second reviewer)
      return;
    }
    const steps = $("wallet-steps");
    steps.textContent = "";
    for (const key of run.steps) {
      if (!WALLET_STEPS[key]) continue;
      const item = document.createElement("li");
      item.textContent = WALLET_STEPS[key]();
      steps.append(item);
    }
    if (run.state === "running") {
      const item = document.createElement("li");
      item.className = "working";
      item.textContent = t("did_working");
      steps.append(item);
    }
    const ended = $("wallet-error");
    ended.hidden = run.state !== "failed";
    ended.textContent = run.state === "failed" ? (WALLET_ERRORS[run.error] || WALLET_ERRORS.wallet_broken)() : "";
    $("result-error").textContent = ended.textContent;
    $("result-error").hidden = run.state !== "failed";
    renderInside(run);
    renderResult(run);
    renderPhone();
    renderMain();
  }

  function check(ok, text) {
    const item = document.createElement("li");
    item.className = ok ? "ok" : "bad";
    item.textContent = text;
    return item;
  }

  // Inside the credential: what the wallet checked, and the claims it holds, as the wallet received them.
  let shownInside = "";

  function renderInside(run) {
    // Rebuilt only when something in it changed, so a credential opened to read stays open between polls.
    const shown = JSON.stringify([lang, run.credentials, run.checked_at]);
    if (shown === shownInside) return;
    shownInside = shown;
    const box = $("inside-list");
    box.textContent = "";
    $("inside").hidden = run.credentials.length === 0;
    $("checked-at").textContent = run.checked_at ? t("checked_at", { time: run.checked_at }) : "";
    for (const credential of run.credentials) {
      const block = document.createElement("article");
      block.className = "held";
      const head = document.createElement("header");
      const format = document.createElement("span");
      format.className = "tag dark";
      format.textContent = credential.format === "mso_mdoc" ? "mdoc" : "SD-JWT VC";
      const type = document.createElement("code");
      type.textContent = credential.type;
      head.append(format, type);
      if (credential.status_value) {
        const status = document.createElement("span");
        status.className = `list-status ${credential.status_value}`;
        status.textContent = (LIST_STATUS[credential.status_value] || LIST_STATUS.unknown)();
        head.append(status);
      }
      const checks = document.createElement("ul");
      checks.className = "checks";
      checks.append(
        check(credential.signature, t(credential.signature ? "chk_signature" : "chk_signature_bad", { signer: credential.signer || "?" })),
        check(credential.digests, t(credential.digests ? "chk_digests" : "chk_digests_bad", { count: credential.disclosures })),
        check(credential.holder_bound, t(credential.holder_bound ? "chk_bound" : "chk_unbound")),
      );
      const facts = document.createElement("dl");
      facts.className = "face";
      const rows = [];
      if (credential.valid_until) rows.push([t("valid_until"), credential.valid_until]);
      if (credential.status) rows.push([t("status_entry"), `#${credential.status.idx}`]);
      fill(facts, [...rows, ...credential.claims]);
      const raw = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = t("raw_title", { size: credential.raw.length });
      const pre = document.createElement("pre");
      pre.className = "raw";
      pre.textContent = credential.raw;
      raw.append(summary, pre);
      block.append(head, checks, facts, raw);
      box.append(block);
    }
  }

  async function act(action, button, body) {
    if (!session) return;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    const asked = session;
    try {
      const view = await call("POST", `${base()}/${action}`, body || {});
      if (session !== asked) return;
      lastView = view; // the steps' words read it
      render(view.step);
      renderWallet(view);
      showError("issue-error", "");
      pollDelay = 600;
      schedule();
    } catch (error) {
      if (session === asked) showError("issue-error", error.message);
    } finally {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }

  function demoWallet(event) {
    const body = {};
    if (joined && lastView && lastView.pin) body.pin = $("demo-pin-value").value.trim();
    act("demo-wallet", event.currentTarget, body);
  }

  function leave() {
    clearTimeout(pollTimer);
    clearInterval(expiryTimer);
    session = null;
    lastStep = null;
    lastView = null;
    lock(false);
    $("issue").classList.remove("after", "stored");
    $("qr").textContent = "";
    $("face").textContent = "";
    $("inside-list").textContent = "";
    shownInside = "";
    $("wallet-box").hidden = true;
    $("inside").hidden = true;
    $("result").hidden = true;
    $("result-error").hidden = true;
    $("result-error").textContent = "";
    $("copy-link").textContent = t("copy_link");
    showError("issue-error", "");
    renderMain();
  }

  function again() {
    if (joined) {
      location.href = "/";
      return;
    }
    leave();
    $("choose").scrollIntoView();
  }

  // The offer's wallet link, for a wallet on another device or for a developer's tools. The clipboard API needs a
  // secure page; elsewhere the older copy command does the same.
  async function copyLink() {
    if (!session) return;
    const link = session.wallet_link;
    let copied = false;
    try {
      await navigator.clipboard.writeText(link);
      copied = true;
    } catch (error) {
      const area = document.createElement("textarea");
      area.value = link;
      area.setAttribute("readonly", "");
      area.className = "offscreen";
      document.body.append(area);
      area.select();
      copied = document.execCommand("copy");
      area.remove();
    }
    $("copy-link").textContent = copied ? t("copied") : t("copy_failed");
  }

  // The phone page: the one offer its reference names.
  async function join() {
    document.body.classList.add("joined");
    lock(true);
    try {
      session = await call("GET", base());
    } catch (error) {
      showError("issue-error", error.status === 404 ? t("offer_gone") : error.message);
      return;
    }
    remember("offer", t("w_h_offer"));
    opened();
    render(session.step);
    renderWallet(session);
    schedule();
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("issue-title").tabIndex = -1;
    for (const input of $("choose").querySelectorAll("input")) {
      input.addEventListener("change", () => {
        if (session) leave(); // another choice: the open offer is left to expire, and a new one can be made
        syncOptions();
      });
    }
    for (const input of document.querySelectorAll('input[name="scan"]')) input.addEventListener("change", syncScan);
    $("copy-link").addEventListener("click", copyLink);
    $("start").addEventListener("click", start);
    $("demo-wallet").addEventListener("click", demoWallet);
    $("w-add").addEventListener("click", demoWallet);
    $("w-decline").addEventListener("click", () => {
      declined = true;
      remember(null, t("w_h_declined"));
      renderPhone();
    });
    $("w-again").addEventListener("click", () => {
      declined = false;
      renderPhone();
    });
    $("w-check-status").addEventListener("click", (event) => act("status", event.currentTarget));
    $("check-status").addEventListener("click", (event) => act("status", event.currentTarget));
    $("result-check-status").addEventListener("click", (event) => act("status", event.currentTarget));
    for (const input of document.querySelectorAll('input[name="mode"]')) {
      input.addEventListener("change", () => setMode(input.value));
    }
    $("release").addEventListener("click", (event) => act("release", event.currentTarget));
    $("refuse").addEventListener("click", (event) => act("refuse", event.currentTarget));
    $("revoke").addEventListener("click", (event) => act("revoke", event.currentTarget));
    $("again").addEventListener("click", again);
    $("language").addEventListener("click", () => {
      lang = lang === "pt" ? "en" : "pt";
      const url = new URL(location.href);
      url.searchParams.set("lang", lang);
      history.replaceState(null, "", url);
      translate();
    });
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && session) {
        pollDelay = 500; // back from the wallet app: catch up at once
        schedule();
      }
    });
    setMode(storedMode() === "advanced" ? "advanced" : "simple");
    syncOptions();
    translate();
    if (joined) join();
  });
})();
