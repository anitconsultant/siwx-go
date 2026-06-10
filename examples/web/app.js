/**
 * app.js — SIWX sign-in flow for Phantom (Solana) and MetaMask (Ethereum).
 * No external dependencies.
 */

const HUB = '';  // same origin

// ---- EIP-55 address checksumming ----
// siwe-go requires EIP-55 format; wallets may return lowercase addresses.

function keccak256(msgBytes) {
  const RC = [
    [0x00000001,0x00000000],[0x00008082,0x00000000],[0x0000808a,0x80000000],
    [0x80008000,0x80000000],[0x0000808b,0x00000000],[0x80000001,0x00000000],
    [0x80008081,0x80000000],[0x00008009,0x80000000],[0x0000008a,0x00000000],
    [0x00000088,0x00000000],[0x80008009,0x00000000],[0x8000000a,0x00000000],
    [0x8000808b,0x00000000],[0x0000008b,0x80000000],[0x00008089,0x80000000],
    [0x00008003,0x80000000],[0x00008002,0x80000000],[0x00000080,0x80000000],
    [0x0000800a,0x00000000],[0x8000000a,0x80000000],[0x80008081,0x80000000],
    [0x00008080,0x80000000],[0x80000001,0x00000000],[0x80008008,0x80000000],
  ];
  const PIL  = [10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1];
  const ROTC = [1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44];
  const RATE = 136;

  function rot32(hi, lo, n) {
    if (n === 0) return [hi, lo];
    if (n < 32) return [(hi << n | lo >>> (32-n)) >>> 0, (lo << n | hi >>> (32-n)) >>> 0];
    n -= 32;
    if (n === 0) return [lo, hi];
    return [(lo << n | hi >>> (32-n)) >>> 0, (hi << n | lo >>> (32-n)) >>> 0];
  }

  function keccakF(st) {
    const C = new Uint32Array(10), D = new Uint32Array(10), B = new Uint32Array(50);
    for (let r = 0; r < 24; r++) {
      for (let x = 0; x < 5; x++) {
        C[2*x]   = (st[2*x]^st[2*(x+5)]^st[2*(x+10)]^st[2*(x+15)]^st[2*(x+20)]) >>> 0;
        C[2*x+1] = (st[2*x+1]^st[2*(x+5)+1]^st[2*(x+10)+1]^st[2*(x+15)+1]^st[2*(x+20)+1]) >>> 0;
      }
      for (let x = 0; x < 5; x++) {
        const [rh,rl] = rot32(C[2*((x+1)%5)+1], C[2*((x+1)%5)], 1);
        D[2*x]   = (C[2*((x+4)%5)]   ^ rl) >>> 0;
        D[2*x+1] = (C[2*((x+4)%5)+1] ^ rh) >>> 0;
        for (let y = 0; y < 5; y++) {
          st[2*(x+5*y)]   = (st[2*(x+5*y)]   ^ D[2*x])   >>> 0;
          st[2*(x+5*y)+1] = (st[2*(x+5*y)+1] ^ D[2*x+1]) >>> 0;
        }
      }
      B[0] = st[0]; B[1] = st[1];
      let src = 1;
      for (let i = 0; i < 24; i++) {
        const dst = PIL[i];
        const [rh, rl] = rot32(st[2*src+1], st[2*src], ROTC[i]);
        B[2*dst] = rl; B[2*dst+1] = rh;
        src = dst;
      }
      for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) {
        st[2*(x+5*y)]   = (B[2*(x+5*y)]   ^ (~B[2*((x+1)%5+5*y)]   & B[2*((x+2)%5+5*y)]  )) >>> 0;
        st[2*(x+5*y)+1] = (B[2*(x+5*y)+1] ^ (~B[2*((x+1)%5+5*y)+1] & B[2*((x+2)%5+5*y)+1])) >>> 0;
      }
      st[0] = (st[0] ^ RC[r][0]) >>> 0;
      st[1] = (st[1] ^ RC[r][1]) >>> 0;
    }
  }

  const st = new Uint32Array(50);
  let ptr = 0;
  const pending = new Uint8Array(RATE);

  function absorbByte(b) {
    pending[ptr] ^= b;
    if (++ptr === RATE) {
      for (let i = 0; i < RATE; i++) {
        const lane = i >> 3, off = i & 7;
        if (off < 4) st[2*lane]   = (st[2*lane]   ^ (pending[i] << (off*8))) >>> 0;
        else         st[2*lane+1] = (st[2*lane+1] ^ (pending[i] << ((off-4)*8))) >>> 0;
      }
      keccakF(st);
      pending.fill(0); ptr = 0;
    }
  }

  for (const b of msgBytes) absorbByte(b);
  absorbByte(0x01);
  pending[RATE-1] ^= 0x80;
  for (let i = 0; i < RATE; i++) {
    const lane = i >> 3, off = i & 7;
    if (off < 4) st[2*lane]   = (st[2*lane]   ^ (pending[i] << (off*8))) >>> 0;
    else         st[2*lane+1] = (st[2*lane+1] ^ (pending[i] << ((off-4)*8))) >>> 0;
  }
  keccakF(st);

  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const lane = i >> 3, off = i & 7;
    out[i] = off < 4 ? (st[2*lane] >>> (off*8)) & 0xff : (st[2*lane+1] >>> ((off-4)*8)) & 0xff;
  }
  return out;
}

function toChecksumAddress(address) {
  const addr = address.toLowerCase().replace(/^0x/, '');
  const hash = keccak256(new TextEncoder().encode(addr));
  const hex  = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  return '0x' + addr.split('').map((c, i) => parseInt(hex[i], 16) >= 8 ? c.toUpperCase() : c).join('');
}

function b64(bytes) {
  let binary = '';
  const arr = new Uint8Array(bytes);
  for (const b of arr) binary += String.fromCharCode(b);
  return btoa(binary);
}

function setStep(steps, id, state, subchecks) {
  return steps.map(s => s.id === id ? { ...s, state, ...(subchecks ? { subchecks } : {}) } : s);
}

function showResult(msg, isError = false) {
  const el = document.getElementById('result');
  el.style.display = 'block';
  el.className = isError ? 'error' : '';
  el.textContent = msg;
}

function initSteps() {
  return [
    { id: 'nonce',  label: 'Fetch nonce from server',  state: 'pending' },
    { id: 'wallet', label: 'Wallet sign-in prompt',    state: 'pending' },
    { id: 'verify', label: 'Server verify signature',  state: 'pending' },
    { id: 'token',  label: 'Issue access token',       state: 'pending' },
    { id: 'linked', label: 'Identity linked',          state: 'pending' },
  ];
}

async function fetchNonce() {
  const r = await fetch(`${HUB}/auth/nonce`);
  if (!r.ok) throw new Error('Nonce fetch failed: ' + r.status);
  const { nonce, domain } = await r.json();
  return { nonce, domain };
}

async function postVerify(message, signature, chainId) {
  const r = await fetch(`${HUB}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: b64(message),
      signature: b64(signature),
      chainId,
    }),
  });
  const json = await r.json();
  if (!r.ok) throw Object.assign(new Error(json.title || 'Verify failed'), { problem: json });
  return json;
}

// ---- Solana / Phantom ----

async function solanaSignIn() {
  const prog = document.getElementById('progress');
  let steps = initSteps();
  prog.steps = steps;

  try {
    steps = setStep(steps, 'nonce', 'active');
    prog.steps = steps;
    const { nonce, domain } = await fetchNonce();
    steps = setStep(steps, 'nonce', 'done');

    steps = setStep(steps, 'wallet', 'active');
    prog.steps = steps;

    if (!window.phantom?.solana?.isPhantom) throw new Error('Phantom wallet not installed');
    const phantom = window.phantom.solana;
    await phantom.connect();
    const result = await phantom.signIn({
      domain,
      nonce,
      statement: 'Sign in to siwx-go demo',
    });

    // Phantom returns: result.signedMessage (Uint8Array), result.signature (Uint8Array)
    const message = result.signedMessage;
    const signature = result.signature;
    steps = setStep(steps, 'wallet', 'done');

    steps = setStep(steps, 'verify', 'active');
    prog.steps = steps;
    const resp = await postVerify(message, signature, 'solana:mainnet');

    // Animate checks with stagger.
    const checks = resp.checks || [];
    steps = setStep(steps, 'verify', 'done', checks);
    prog.steps = steps;

    await animateChecks(prog, steps, checks);

    steps = setStep(steps, 'token', 'active');
    prog.steps = steps;
    await delay(150);
    steps = setStep(steps, 'token', 'done');
    steps = setStep(steps, 'linked', 'done');
    prog.steps = steps;

    showResult(`Token (first 40 chars): ${resp.token.substring(0, 40)}...`);
  } catch (err) {
    const failId = steps.find(s => s.state === 'active')?.id;
    if (failId) steps = setStep(steps, failId, 'failed');
    prog.steps = steps;
    showResult(err.problem?.detail || err.message, true);
  }
}

// ---- EVM / MetaMask ----

async function evmSignIn() {
  const prog = document.getElementById('progress');
  let steps = initSteps();
  prog.steps = steps;

  try {
    steps = setStep(steps, 'nonce', 'active');
    prog.steps = steps;
    const { nonce, domain } = await fetchNonce();
    steps = setStep(steps, 'nonce', 'done');

    steps = setStep(steps, 'wallet', 'active');
    prog.steps = steps;

    if (!window.ethereum) throw new Error('MetaMask not installed');
    const [rawAddress] = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const address = toChecksumAddress(rawAddress);
    const chainIdHex = await window.ethereum.request({ method: 'eth_chainId' });
    const chainIdDec = parseInt(chainIdHex, 16);
    const issuedAt = new Date().toISOString();
    const expirationTime = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const uri = window.location.origin + '/';

    const siweMsg = [
      `${domain} wants you to sign in with your Ethereum account:`,
      address,
      '',
      'Sign in to siwx-go demo',
      '',
      `URI: ${uri}`,
      'Version: 1',
      `Chain ID: ${chainIdDec}`,
      `Nonce: ${nonce}`,
      `Issued At: ${issuedAt}`,
      `Expiration Time: ${expirationTime}`,
    ].join('\n');

    const msgBytes = new TextEncoder().encode(siweMsg);
    const hexMsg = '0x' + Array.from(msgBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const hexSig = await window.ethereum.request({ method: 'personal_sign', params: [hexMsg, address] });

    // Convert hex sig to bytes.
    const sigBytes = new Uint8Array(hexSig.slice(2).match(/.{2}/g).map(b => parseInt(b, 16)));
    steps = setStep(steps, 'wallet', 'done');

    steps = setStep(steps, 'verify', 'active');
    prog.steps = steps;
    const resp = await postVerify(msgBytes, sigBytes, `eip155:${chainIdDec}`);

    const checks = resp.checks || [];
    steps = setStep(steps, 'verify', 'done', checks);
    prog.steps = steps;

    await animateChecks(prog, steps, checks);

    steps = setStep(steps, 'token', 'active');
    prog.steps = steps;
    await delay(150);
    steps = setStep(steps, 'token', 'done');
    steps = setStep(steps, 'linked', 'done');
    prog.steps = steps;

    showResult(`Token (first 40 chars): ${resp.token.substring(0, 40)}...`);
  } catch (err) {
    const failId = steps.find(s => s.state === 'active')?.id;
    if (failId) steps = setStep(steps, failId, 'failed');
    prog.steps = steps;
    showResult(err.problem?.detail || err.message, true);
  }
}

async function animateChecks(prog, steps, checks) {
  for (let i = 0; i < checks.length; i++) {
    await delay(150);
    // Progressively reveal checks.
    const partial = checks.slice(0, i + 1);
    steps = setStep(steps, 'verify', 'done', partial);
    prog.steps = [...steps];
  }
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ---- Event bindings ----
document.getElementById('btn-solana').addEventListener('click', solanaSignIn);
document.getElementById('btn-evm').addEventListener('click', evmSignIn);
