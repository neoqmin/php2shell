// Command generator for php2shell_remote.py.
// Runs entirely in the browser: the URL is never sent anywhere.
// Security: the URL ends up inside a shell command the user will paste,
// so anything that is not a plain URL character is REJECTED, not escaped.
(function () {
  "use strict";

  var TAG = "v0.1.0";
  var RAW = "https://raw.githubusercontent.com/neoqmin/php2shell/" + TAG + "/";
  var SHA_REMOTE = "3c7fd2efb8f624c2c244919e8597fb2d916728269dcff3a98b43758e84fd74dc";

  // Characters allowed in the final URL. Excludes ' " ` $ ; | & < > ( ) { } \ ^
  // whitespace and control characters, so the URL is inert in both
  // POSIX shells and PowerShell even inside single quotes.
  var SAFE = /^[A-Za-z0-9\-._~:\/?#\[\]@!*+,=%]+$/;

  var form = document.getElementById("gen");
  if (!form) return;
  var input = document.getElementById("target");
  var authorized = document.getElementById("authorized");
  var errBox = document.getElementById("gen-error");
  var out = document.getElementById("gen-out");
  var lang = document.documentElement.lang || "ko";
  var msg = form.dataset;

  function validate(raw) {
    var s = raw.trim();
    if (!s) return { error: msg.errEmpty };
    // Reject shell metacharacters up front too, instead of letting the URL
    // parser silently percent-encode or rewrite them (e.g. "\" -> "/").
    if (/[\s\u0000-\u001f\u007f'"`$;|&<>(){}\\^]/.test(s)) return { error: msg.errChars };
    var u;
    try { u = new URL(s); } catch (e) { return { error: msg.errScheme }; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return { error: msg.errScheme };
    if (u.username || u.password) return { error: msg.errCred };
    // href is normalized (IDN -> punycode, non-ASCII path -> %XX); check it, not the input.
    if (!SAFE.test(u.href)) return { error: msg.errChars };
    return { url: u.href };
  }

  function commands(url) {
    var file = "php2shell_remote.py";
    var run = file + " '" + url + "' --lang " + lang;
    return {
      linux: [
        "curl -fsSLO " + RAW + file,
        "echo '" + SHA_REMOTE + "  " + file + "' | sha256sum -c -",
        "python3 " + run
      ].join("\n"),
      macos: [
        "curl -fsSLO " + RAW + file,
        "echo '" + SHA_REMOTE + "  " + file + "' | shasum -a 256 -c -",
        "python3 " + run
      ].join("\n"),
      windows: [
        "$env:PYTHONIOENCODING = 'utf-8'",
        "Invoke-WebRequest -UseBasicParsing -Uri " + RAW + file + " -OutFile " + file,
        "if ((Get-FileHash .\\" + file + " -Algorithm SHA256).Hash -ne '" + SHA_REMOTE + "') { throw 'SHA256 mismatch' }",
        "python .\\" + run
      ].join("\n")
    };
  }

  function show(os) {
    var tabs = out.querySelectorAll(".tabs button");
    for (var i = 0; i < tabs.length; i++) {
      var on = tabs[i].dataset.os === os;
      tabs[i].setAttribute("aria-selected", on ? "true" : "false");
      document.getElementById("cmd-" + tabs[i].dataset.os).hidden = !on;
    }
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    errBox.textContent = "";
    out.hidden = true;
    if (!authorized.checked) { errBox.textContent = msg.errAuth; return; }
    var r = validate(input.value);
    if (r.error) { errBox.textContent = r.error; return; }
    var c = commands(r.url);
    document.querySelector("#cmd-linux pre").textContent = c.linux;
    document.querySelector("#cmd-macos pre").textContent = c.macos;
    document.querySelector("#cmd-windows pre").textContent = c.windows;
    out.hidden = false;
    show(/Win/.test(navigator.platform) ? "windows" : /Mac/.test(navigator.platform) ? "macos" : "linux");
  });

  out.addEventListener("click", function (ev) {
    var t = ev.target;
    if (t.dataset && t.dataset.os) show(t.dataset.os);
  });

  // Copy buttons for every code block on the page.
  var boxes = document.querySelectorAll(".codebox");
  for (var i = 0; i < boxes.length; i++) {
    (function (box) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "copy";
      b.textContent = msg.copy;
      b.addEventListener("click", function () {
        var text = box.querySelector("pre").textContent;
        if (!navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
          b.textContent = msg.copied;
          setTimeout(function () { b.textContent = msg.copy; }, 1500);
        });
      });
      box.appendChild(b);
    })(boxes[i]);
  }

  // Expose the validator for manual testing from the console.
  window.php2shellValidate = validate;
})();
