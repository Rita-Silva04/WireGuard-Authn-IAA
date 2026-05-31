/*
 * Password challenge-response (STEPS.md §1.6).
 *
 * The browser:
 *   1. Fetches the challenge: { salt_b64, nonce_b64 } from
 *      /oauth/mfa/<sid>/password/challenge.
 *   2. Derives verifier = scrypt(password, salt, N=2^14, r=8, p=1, 32 B).
 *   3. Computes proof = HMAC-SHA256(verifier, nonce).
 *   4. POSTs { proof: base64(proof) } to /oauth/mfa/<sid>/password.
 *
 * The raw password never leaves the page.
 */
(function () {
  "use strict";

  function b64decode(s) {
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  function b64encode(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  async function submitProof(form) {
    const status = document.getElementById("pw-status");
    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    status.textContent = "Computing password proof — this may take a moment…";

    const password = form.password.value;
    if (!password) {
      status.textContent = "Password required.";
      button.disabled = false;
      return false;
    }

    try {
      const sessionId = form.dataset.sessionId;
      const chResp = await fetch(`/oauth/mfa/${sessionId}/password/challenge`,
                                 { credentials: "same-origin" });
      if (!chResp.ok) {
        let message = "Authentication is temporarily unavailable. Try again later.";
        try {
          const data = await chResp.json();
          if (data.message) message = data.message;
        } catch (_) {}
        throw new Error(message);
      }
      const challenge = await chResp.json();

      const salt  = b64decode(challenge.salt_b64);
      const nonce = b64decode(challenge.nonce_b64);

      // scrypt verifier (§1.6 parameters)
      const verifier = await scryptDerive(password, salt,
        { N: 16384, r: 8, p: 1, dkLen: 32 });

      // HMAC-SHA256(verifier, nonce)
      const hmacKey = await crypto.subtle.importKey(
        "raw", verifier,
        { name: "HMAC", hash: "SHA-256" },
        false, ["sign"]
      );
      const proofBuf = await crypto.subtle.sign("HMAC", hmacKey, nonce);
      const proofB64 = b64encode(new Uint8Array(proofBuf));

      // POST a synthetic form containing only `proof` so the password is
      // not included in the submitted form data.
      const submission = document.createElement("form");
      submission.method = "POST";
      submission.action = form.action;
      const proofField = document.createElement("input");
      proofField.type  = "hidden";
      proofField.name  = "proof";
      proofField.value = proofB64;
      submission.appendChild(proofField);
      document.body.appendChild(submission);
      submission.submit();
    } catch (err) {
      console.error(err);
      status.textContent = err.message;
      button.disabled = false;
    }
    return false;
  }

  window.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("pw-form");
    if (form) {
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        submitProof(form);
      });
    }
  });
})();
