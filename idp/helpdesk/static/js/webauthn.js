function b64ToBuffer(b64) {
    const s = b64.replace(/-/g,'+').replace(/_/g,'/');
    const pad = s.length%4===0?'':'='.repeat(4-s.length%4);
    return Uint8Array.from(atob(s+pad),c=>c.charCodeAt(0)).buffer;
}
function bufferToB64url(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function prepareRegOptions(opts) {
    opts.challenge = b64ToBuffer(opts.challenge);
    if (opts.user?.id) opts.user.id = b64ToBuffer(opts.user.id);
    if (opts.excludeCredentials)
        opts.excludeCredentials = opts.excludeCredentials.map(c=>({...c,id:b64ToBuffer(c.id)}));
    return opts;
}
function showMsg(text, type) {
    const el = document.getElementById('msg');
    el.innerHTML = `<div class="${type}" style="margin-top:10px">${text}</div>`;
    el.style.display='block';
}

async function registerKey(username) {
    const name = document.getElementById('key-name').value || 'YubiKey';
    try {
        showMsg('Starting registration…', 'ok');
        const optResp = await fetch(`/user/${username}/fido2/start`, {method:'POST'});
        const opts    = prepareRegOptions(await optResp.json());

        showMsg('Touch your security key…', 'ok');
        const cred = await navigator.credentials.create({publicKey: opts});

        const body = {
            id:    cred.id,
            rawId: bufferToB64url(cred.rawId),
            type:  cred.type,
            response: {
                attestationObject: bufferToB64url(cred.response.attestationObject),
                clientDataJSON:    bufferToB64url(cred.response.clientDataJSON),
                transports: cred.response.getTransports ? cred.response.getTransports() : [],
            }
        };

        const res  = await fetch(`/user/${username}/fido2/finish?name=${encodeURIComponent(name)}`,
            {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
        const data = await res.json();

        if (res.ok) {
            showMsg('Security key registered! Refreshing…', 'ok');
            setTimeout(()=>window.location.reload(), 1200);
        } else {
            showMsg(data.error, 'err');
        }
    } catch(e) {
        showMsg(e.message, 'err');
    }
}
