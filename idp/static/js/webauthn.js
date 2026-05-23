function b64ToBuffer(b64) {
    const s = b64.replace(/-/g,'+').replace(/_/g,'/');
    const pad = s.length%4===0?'':'='.repeat(4-s.length%4);
    return Uint8Array.from(atob(s+pad),c=>c.charCodeAt(0)).buffer;
}
function bufferToB64url(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function prepareAuthOptions(opts) {
    opts.challenge = b64ToBuffer(opts.challenge);
    if (opts.allowCredentials)
        opts.allowCredentials = opts.allowCredentials.map(c=>({...c,id:b64ToBuffer(c.id)}));
    return opts;
}

async function startFido2(sessionId) {
    const btn = document.getElementById('fido2-btn');
    const msg = document.getElementById('fido2-msg');
    btn.disabled = true;
    msg.innerHTML = '<div class="info" style="margin-top:12px">Waiting for YubiKey…</div>';

    try {
        const optResp = await fetch(`/oauth/mfa/${sessionId}/fido2/start`);
        const opts    = prepareAuthOptions(await optResp.json());
        const cred    = await navigator.credentials.get({publicKey: opts});

        const body = {
            id:    cred.id,
            rawId: bufferToB64url(cred.rawId),
            type:  cred.type,
            response: {
                authenticatorData: bufferToB64url(cred.response.authenticatorData),
                clientDataJSON:    bufferToB64url(cred.response.clientDataJSON),
                signature:         bufferToB64url(cred.response.signature),
                userHandle: cred.response.userHandle
                    ? bufferToB64url(cred.response.userHandle) : null,
            }
        };

        const res = await fetch(`/oauth/mfa/${sessionId}/fido2/finish`, {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify(body)
        });
        const data = await res.json();

        if (res.ok) {
            msg.innerHTML = '<div class="ok" style="margin-top:12px">✅ YubiKey verified! Redirecting…</div>';
            setTimeout(()=>{ window.location=`/oauth/mfa/${sessionId}`; }, 800);
        } else {
            msg.innerHTML = `<div class="err" style="margin-top:12px">❌ ${data.error}</div>`;
            btn.disabled = false;
        }
    } catch(e) {
        msg.innerHTML = `<div class="err" style="margin-top:12px">❌ ${e.message}</div>`;
        btn.disabled = false;
    }
}
