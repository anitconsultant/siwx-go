/**
 * app.js — SIWX sign-in flow for Phantom (Solana) and MetaMask (Ethereum).
 * No external dependencies.
 */

const HUB = '';  // same origin

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
  const { nonce } = await r.json();
  return nonce;
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
    const nonce = await fetchNonce();
    steps = setStep(steps, 'nonce', 'done');

    steps = setStep(steps, 'wallet', 'active');
    prog.steps = steps;

    if (!window.phantom?.solana?.isPhantom) throw new Error('Phantom wallet not installed');
    const phantom = window.phantom.solana;
    await phantom.connect();

    const domain = window.location.hostname;
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
    const nonce = await fetchNonce();
    steps = setStep(steps, 'nonce', 'done');

    steps = setStep(steps, 'wallet', 'active');
    prog.steps = steps;

    if (!window.ethereum) throw new Error('MetaMask not installed');
    const [address] = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const chainIdHex = await window.ethereum.request({ method: 'eth_chainId' });
    const chainIdDec = parseInt(chainIdHex, 16);

    const domain = window.location.hostname;
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
