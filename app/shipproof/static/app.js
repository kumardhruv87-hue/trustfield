/* Trustfield front-end: vanilla JS, no framework, no inline handlers (CSP-safe). */
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  function setHTML(el, html) {
    var doc = new DOMParser().parseFromString("<div>" + String(html == null ? "" : html) + "</div>", "text/html");
    var holder = doc.body.firstChild;
    while (el.firstChild) el.removeChild(el.firstChild);
    if (holder) while (holder.firstChild) el.appendChild(holder.firstChild);
  }

  function meta(name) {
    var tag = document.querySelector('meta[name="' + name + '"]');
    return tag ? tag.getAttribute("content") || "" : "";
  }

  function postJSON(url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          var err = new Error(data && data.error ? data.error : "Something went wrong (" + res.status + ")");
          err.status = res.status;
          throw err;
        }
        return data;
      });
    });
  }

  function severityPill(sev) {
    var labels = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
    return '<span class="pill sev-' + esc(sev) + '">' + esc(labels[sev] || sev) + "</span>";
  }

  function countsHTML(counts) {
    var order = ["critical", "high", "medium", "low", "info"];
    var labels = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
    return '<div class="counts">' + order.map(function (sev) {
      var n = (counts && counts[sev]) || 0;
      return '<div class="count sev-' + sev + '"><span class="count-n">' + n + '</span>' +
        '<span class="count-l">' + labels[sev] + "</span></div>";
    }).join("") + "</div>";
  }

  /* â”€â”€ landing page scanner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
  var form = $("#scan-form");
  if (form) {
    var acquisitionSource = "direct";
    try {
      var campaign = new URLSearchParams(window.location.search).get("utm_source");
      acquisitionSource = campaign || sessionStorage.getItem("tf_source") || "direct";
      acquisitionSource = acquisitionSource.toLowerCase();
      if (["direct", "google", "linkedin", "youtube", "x", "community"].indexOf(acquisitionSource) < 0) acquisitionSource = "other";
      sessionStorage.setItem("tf_source", acquisitionSource);
    } catch (e) {}
    function track(event) {
      postJSON("/api/events", { event: event, source: acquisitionSource }).catch(function () {});
    }
    track("visit");
    var kind = "url";
    var statusBox = $("#scan-status");
    var resultBox = $("#scan-result");
    var submitBtn = $("#scan-btn");
    var targetInput = $("#target");
    var targetLabel = $("#target-label");
    var targetHint = $("#target-hint");
    var emailInput = $("#email");
    var aiInput = $("#has-ai");
    var consentInput = $("#consent");

    var copy = {
      url: {
        label: "Your app URL",
        hint: "Public URL of the page your users open. We only read public pages — never your database.",
        placeholder: "https://myapp.vercel.app"
      },
      repo: {
        label: "Public GitHub repo (optional)",
        hint: "Example: https://github.com/yourname/your-app — we download a read-only copy and discard it.",
        placeholder: "https://github.com/yourname/your-app"
      }
    };

    $$(".tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        kind = tab.getAttribute("data-kind") || "url";
        $$(".tab").forEach(function (other) {
          var active = other === tab;
          other.classList.toggle("active", active);
          other.setAttribute("aria-selected", active ? "true" : "false");
        });
        targetLabel.textContent = copy[kind].label;
        targetHint.textContent = copy[kind].hint;
        targetInput.placeholder = copy[kind].placeholder;
        targetInput.value = "";
        targetInput.focus();
      });
    });

    var steps = [
      "Checking HTTPS and headers…",
      "Reading your public pages…",
      "Scanning your JavaScript bundle for keys…",
      "Probing for exposed .env / .git files…",
      "Checking public exposure signals…",
      "Scoring what we found…"
    ];
    var timer = null;

    function startProgress() {
      var i = 0;
      statusBox.className = "scan-status";
      setHTML(statusBox, '<span class="scan-beacon" aria-hidden="true"><i></i><b></b></span>' + esc(steps[0]));
      statusBox.classList.remove("hidden");
      clearInterval(timer);
      timer = setInterval(function () {
        i = (i + 1) % steps.length;
        setHTML(statusBox, '<span class="scan-beacon" aria-hidden="true"><i></i><b></b></span>' + esc(steps[i]));
      }, 2600);
    }

    function stopProgress() {
      clearInterval(timer);
      statusBox.classList.add("hidden");
    }

    function showError(message) {
      track("scan_error");
      stopProgress();
      statusBox.className = "scan-status error";
      statusBox.textContent = message;
      statusBox.classList.remove("hidden");
    }

    function payLinkFor(id) {
      return "/pay/" + encodeURIComponent(id);
    }

    function renderResult(data) {
      var score = Number(data.score || 0);
      var locked = !!data.locked;
      var pay = payLinkFor(data.id);
      var mail = "mailto:" + meta("sp-contact") + "?subject=" + encodeURIComponent("Unlock report " + (data.id || ""));
      var unlockHref = pay || mail;
      var priceINR = meta("sp-price-inr");
      var priceUSD = meta("sp-price-usd");

      var preview = (data.teaser || data.preview_findings || []).slice(0, 40).map(function (f) {
        return '<div class="mini-finding">' + severityPill(f.severity) +
          "<span>" + esc(f.title) + "</span>" +
          '<span class="ev">' + (locked ? "evidence + fix locked" : "") + "</span></div>";
      }).join("");

      var actions = (data.top_actions || []).map(function (a, i) {
        return '<li><span class="num">' + (i + 1) + "</span><div>" +
          '<div class="action-title">' + esc(a.title) + "</div>" +
          '<div class="action-meta">' + severityPill(a.severity) +
          '<span class="effort">~' + esc(a.effort) + "</span></div></div></li>";
      }).join("");

      setHTML(resultBox,
        '<div class="result-head"><div class="ring small" style="--score:' + score + '">' +
          '<div class="ring-inner"><b>' + score + "</b><span>" + esc(data.grade || "") + "</span></div></div>" +
          '<div class="result-text"><h3>' + esc(data.headline || "") + "</h3>" +
          "<p>" + esc(data.verdict || "") + "</p>" +
          '<p class="fine">' + esc(data.target || "") + " · " + (data.total || 0) + " findings" +
          (data.checks_total ? " · " + data.checks_total + " checks run" : "") + "</p></div></div>" +
        countsHTML(data.counts) +
        ((data.summary_en || data.summary_hi) ? '<div class="hinglish"><strong>The short version:</strong> ' + esc(data.summary_en || data.summary_hi) + "</div>" : "") +
        (actions ? '<h4>Fix these first</h4><ol class="actions">' + actions + "</ol>" : "") +
        (preview ? '<div class="mini-finding-grid">' + preview + "</div>" : "") +
        '<div class="result-cta">' +
          '<a class="btn primary" href="' + esc(data.report_url || "#") + '">View my results</a>' +
          (locked && Number(data.total) > 0
            ? '<a class="btn ghost unlock-btn" href="' + esc(unlockHref) + '">Get fixes + PDF + re-check — ₹' +
              esc(priceINR) + "</a>"
            : "") +
        "</div>" +
        '<p class="fine">' +
          (locked
            ? (Number(data.total) > 0 ? "Your results are free. Optional ₹" + esc(priceINR) + " report: evidence, fix prompts, PDF and one re-check. No subscription." : "No issues found in these checks. No fixes to buy. View your free results and the limits of this scan.")
            : "Full report unlocked.") +
        "</p>");

      resultBox.classList.remove("hidden");
      resultBox.scrollIntoView({ behavior: "smooth", block: "center" });

      var unlock = $(".unlock-btn", resultBox);
      if (unlock) {
        unlock.addEventListener("click", function () {
          var email = (emailInput.value || "").trim();
          if (email && email.indexOf("@") > 0) {
            postJSON("/api/lead", { email: email, scan_id: data.id }).catch(function () {});
          }
        });
      }
    }

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var target = (targetInput.value || "").trim();
      if (target.length < 3) {
        showError("Enter the URL or GitHub repo you want to scan.");
        targetInput.focus();
        return;
      }
      if (!consentInput.checked) {
        showError("Please confirm you own this app or have permission to test it.");
        consentInput.focus();
        return;
      }
      if (emailInput && emailInput.value && !emailInput.validity.valid) {
        showError("Enter a valid email address, or leave email blank.");
        emailInput.focus();
        return;
      }
      track("scan_start");
      submitBtn.disabled = true;
      submitBtn.textContent = "Scanning…";
      resultBox.classList.add("hidden");
      startProgress();

      postJSON("/api/scan", {
        kind: kind,
        source: acquisitionSource,
        target: target,
        has_ai: !!(aiInput && aiInput.checked),
        email: (emailInput && emailInput.value || "").trim(),
        consent: true
      }).then(function (data) {
        stopProgress();
        if (!data || data.ok === false) {
          showError((data && data.error) || "The scan did not finish. Try again.");
          return;
        }
        renderResult(data);
      }).catch(function (error) {
        showError(error.message || "The scan did not finish. Try again in a minute.");
      }).then(function () {
        submitBtn.disabled = false;
        submitBtn.textContent = "Scan my app — free";
      });
    });
  }

  /* â”€â”€ report page: print, copy prompts, grade answers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
  var printBtn = $(".print-btn");
  if (printBtn) {
    printBtn.addEventListener("click", function () { window.print(); });
  }

  $$(".copy-btn").forEach(function (button) {
    button.addEventListener("click", function () {
      var card = button.closest(".kit-card");
      var pre = card ? $(".kit-payload", card) : null;
      var text = pre ? pre.textContent : "";
      var done = function () {
        var old = button.textContent;
        button.textContent = "Copied";
        setTimeout(function () { button.textContent = old; }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(function () {});
      } else {
        var area = document.createElement("textarea");
        area.value = text;
        document.body.appendChild(area);
        area.select();
        try { document.execCommand("copy"); done(); } catch (err) { /* ignore */ }
        document.body.removeChild(area);
      }
    });
  });

  var scanId = meta("sp-scan");
  var graded = {};

  function saveKit() {
    if (!scanId) return;
    var results = Object.keys(graded).map(function (key) {
      return { payload_id: key, response: graded[key].response };
    });
    if (!results.length) return;
    postJSON("/api/scan/" + scanId + "/kit", { results: results }).catch(function () {});
  }

  function renderVerdict(card, data) {
    var existing = $(".verdict", card);
    var verdict = (data && data.verdict) || "UNCLEAR";
    var advice = (data && data.advice) || "";
    var evidence = (data && data.evidence) || "";
    if (!existing) {
      existing = document.createElement("div");
      card.appendChild(existing);
    }
    existing.className = "verdict verdict-" + verdict.toLowerCase();
    setHTML(existing, esc(verdict) + "<span>" + esc(evidence || advice) + "</span>");
  }

  $$(".grade-btn").forEach(function (button) {
    button.addEventListener("click", function () {
      var wrap = button.closest(".kit-test");
      var card = button.closest(".kit-card");
      if (!wrap || !card) return;
      var textarea = $("textarea", wrap);
      var response = textarea ? textarea.value.trim() : "";
      var payloadId = card.getAttribute("data-payload");
      if (response.length < 3) {
        renderVerdict(card, { verdict: "UNCLEAR", advice: "Paste the reply your app gave first." });
        return;
      }
      button.disabled = true;
      postJSON("/api/grade", { payload_id: payloadId, response: response }).then(function (data) {
        graded[payloadId] = { response: response };
        renderVerdict(card, data);
        saveKit();
      }).catch(function (error) {
        renderVerdict(card, { verdict: "UNCLEAR", advice: error.message || "Could not grade that answer." });
      }).then(function () {
        button.disabled = false;
      });
    });
  });

  /* copy-paste fix prompt for the AI builder */
  $$(".copy-fix-btn").forEach(function (button) {
    button.addEventListener("click", function () {
      var text = button.getAttribute("data-prompt") || "";
      var done = function () {
        var old = button.textContent;
        button.textContent = "Copied";
        setTimeout(function () { button.textContent = old; }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(function () {});
      } else {
        var area = document.createElement("textarea");
        area.value = text;
        document.body.appendChild(area);
        area.select();
        try { document.execCommand("copy"); done(); } catch (err) { /* ignore */ }
        document.body.removeChild(area);
      }
    });
  });
})();


/* After Razorpay redirects back with ?paid=1, poll until the webhook unlocks the report. */
(function () {
  try {
    var q = new URLSearchParams(window.location.search);
    if (q.get("paid") !== "1") return;
    var scanTag = document.querySelector('meta[name="sp-scan"]');
    var paidTag = document.querySelector('meta[name="sp-unlocked"]');
    var scan = scanTag && scanTag.content;
    if (!scan || (paidTag && paidTag.content)) return;
    var notice = document.createElement("p");
    notice.className = "note";
    notice.textContent = "Confirming your payment. This page will update when your report is ready…";
    var report = document.querySelector("main");
    if (report) report.insertBefore(notice, report.firstChild);
    var tries = 0;
    var timer = setInterval(function () {
      tries += 1;
      fetch("/api/scan/" + encodeURIComponent(scan)).then(function (r) { return r.json(); }).then(function (d) {
        if (d && d.locked === false) { clearInterval(timer); window.location.reload(); }
        else if (tries >= 24) {
          clearInterval(timer);
          notice.textContent = "Payment confirmation is taking longer than usual. Keep your payment ID and email support using the contact in the report. You do not need to pay again.";
        }
      }).catch(function () {});
    }, 2500);
  } catch (e) {}
})();

/* Report copilot: ask questions grounded in this report. */
(function () {
  var panel = document.querySelector(".ai-panel");
  if (!panel) return;
  var input = document.getElementById("ai-question");
  var btn = document.getElementById("ai-ask");
  var log = document.getElementById("ai-log");
  var note = document.getElementById("ai-note");
  var scan = panel.getAttribute("data-scan") || "";
  function add(role, text) {
    var row = document.createElement("div");
    row.className = "ai-msg ai-" + role;
    var span = document.createElement("span");
    span.textContent = text;
    row.appendChild(span);
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
  }
  function ask() {
    var q = (input.value || "").trim();
    if (q.length < 3 || btn.disabled) return;
    btn.disabled = true;
    note.textContent = "Thinking...";
    add("you", q);
    input.value = "";
    fetch("/api/report/" + encodeURIComponent(scan) + "/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: q })
    }).then(function (res) { return res.json().then(function (data) { return { ok: res.ok, data: data }; }); })
      .then(function (out) {
        if (out.data && out.data.ok) add("ai", out.data.answer);
        else add("ai", (out.data && out.data.error) || "Could not answer right now.");
      })
      .catch(function () { add("ai", "Network error. Try again."); })
      .then(function () {
        btn.disabled = false;
        note.textContent = "Answers are AI-generated from your report. Not a new security test.";
      });
  }
  if (btn) btn.addEventListener("click", ask);
  if (input) input.addEventListener("keydown", function (e) { if (e.key === "Enter") ask(); });
})();

/* Agency handover: unlock a report with a credit code. */
(function () {
  var btn = document.getElementById("agency-unlock");
  if (!btn) return;
  var codeInput = document.getElementById("agency-code");
  var clientInput = document.getElementById("agency-client");
  var note = document.getElementById("agency-note");
  var scan = (document.querySelector('meta[name="sp-scan"]') || {}).content || "";
  btn.addEventListener("click", function () {
    var code = (codeInput.value || "").trim();
    if (code.length < 5) return;
    btn.disabled = true;
    note.classList.remove("hidden");
    note.textContent = "Checking code...";
    fetch("/unlock-code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: code, scan_id: scan, client: (clientInput.value || "").trim() })
    }).then(function (res) { return res.json().then(function (data) { return { status: res.status, data: data }; }); })
      .then(function (out) {
        if (out.data && out.data.ok) { note.textContent = "Unlocked. Reloading..."; window.location.reload(); }
        else { note.textContent = (out.data && out.data.error) || "That code did not work."; btn.disabled = false; }
      })
      .catch(function () { note.textContent = "Network error. Try again."; btn.disabled = false; });
  });
})();
