// Certificate Checker Web: copy buttons, drop zone and file-size hint. No dynamic code, no HTML injection, no inline handlers.
"use strict";
(function () {
  function copyText(btn) {
    var code = btn.parentElement && btn.parentElement.querySelector("code");
    if (!code) return;
    var text = code.textContent || "";
    function selectFallback() {
      var r = document.createRange();
      r.selectNodeContents(code);
      var s = window.getSelection();
      s.removeAllRanges();
      s.addRange(r);
      btn.textContent = "Selected: press Ctrl/Cmd+C";
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = "Copy"; }, 1500);
      }, selectFallback);
    } else {
      selectFallback();
    }
  }
  document.addEventListener("click", function (e) {
    var t = e.target;
    if (t instanceof HTMLElement && t.classList.contains("copy")) copyText(t);
  });
  document.addEventListener("change", function (e) {
    var t = e.target;
    if (!(t instanceof HTMLInputElement) || t.type !== "file" || !t.form) return;
    var max = parseInt(t.form.getAttribute("data-max-bytes") || "0", 10);
    var total = 0;
    for (var i = 0; i < (t.files ? t.files.length : 0); i++) total += t.files[i].size;
    var hint = document.getElementById("filesize");
    if (hint) {
      hint.textContent = (total / 1024).toFixed(1) + " KB selected" + (max && total > max ? ": over the limit" : "");
      hint.className = "span " + (max && total > max ? "sev-fail" : "muted");
    }
  });
  document.addEventListener("dragover", function (e) {
    if (e.target instanceof HTMLElement && e.target.closest("#drop")) e.preventDefault();
  });
  document.addEventListener("drop", function (e) {
    var zone = e.target instanceof HTMLElement && e.target.closest("#drop");
    if (!zone || !e.dataTransfer) return;
    e.preventDefault();
    var input = zone.querySelector("input[type=file]");
    if (input) {
      input.files = e.dataTransfer.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    }
  });
})();
