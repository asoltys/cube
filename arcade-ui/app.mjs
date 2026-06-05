// Cube Lottery — browser client.
// Generates keys, builds the Call SBE sighash, and BLS-signs it entirely in the
// browser (verified byte-for-byte against the Rust engine). The engine only
// receives the signed call + signature and executes it.

import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

const Fr = bls.fields.Fr;
const enc = new TextEncoder();

// ---------- byte helpers ----------
const hx = (u) => Array.from(u).map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(h.match(/.{1,2}/g).map((x) => parseInt(x, 16)));
const beToBig = (u) => { let x = 0n; for (const c of u) x = (x << 8n) | BigInt(c); return x; };
const cat = (...a) => {
  const arr = a.map((x) => (x instanceof Uint8Array ? x : Uint8Array.from(x)));
  const n = arr.reduce((s, x) => s + x.length, 0);
  const o = new Uint8Array(n); let i = 0;
  for (const x of arr) { o.set(x, i); i += x.length; }
  return o;
};
const u16le = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64le = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };

// ---------- Cube tagged hashes ----------
function taggedHash256(tag, msg) { const t = sha256(enc.encode(tag)); return sha256(cat(t, t, msg)); }
function taggedHash512(tag, msg) { const t = sha512(enc.encode(tag)); return sha512(cat(t, t, msg)); }

// ---------- keys ----------
function deriveBlsSecretBytes(secp32) { return taggedHash512('Cube/bls/secretkey', secp32).slice(0, 48); }
function blsScalar(secp32) { return beToBig(deriveBlsSecretBytes(secp32)) % Fr.ORDER; }
function blsPublicKey(secp32) { return bls.G1.Point.BASE.multiply(blsScalar(secp32)).toBytes(); }
function accountKey(secp32) { return schnorr.getPublicKey(secp32); } // x-only, 32 bytes

function newIdentity() {
  const secp = crypto.getRandomValues(new Uint8Array(32));
  return {
    secp: hx(secp),
    accountKey: hx(accountKey(secp)),
    blsKey: hx(blsPublicKey(secp)),
  };
}

// ---------- Call SBE (must match Rust encode_sbe) ----------
function encodeRegisteredAccountSBE(accountKey32, registeryIndex, blsKey48) {
  return cat([0x02], accountKey32, u64le(registeryIndex), blsKey48);
}
function encodeContractSBE(contractId32, registeryIndex) {
  return cat(contractId32, u64le(registeryIndex));
}
// calldata: u32 count, then each element. Only Payable (0x09 + u32) is needed here.
function encodeCalldataSBE(calldata) {
  let body = u32le(calldata.length);
  for (const el of calldata) {
    if (el.type === 'payable') body = cat(body, [0x09], u32le(el.value));
    else throw new Error('unsupported calldata type ' + el.type);
  }
  return body;
}
function encodeCallSBE(c) {
  const account = encodeRegisteredAccountSBE(fromHex(c.accountKey), c.registeryIndex, fromHex(c.blsKey));
  const contract = encodeContractSBE(fromHex(c.contractId), c.contractRegisteryIndex);
  const calldata = encodeCalldataSBE(c.calldata);
  return cat(
    [0x01],
    u32le(account.length), account,
    u32le(contract.length), contract,
    u16le(c.methodIndex),
    u32le(calldata.length), calldata,
    [0x00],               // ops_budget: None
    u64le(c.opsPrice),    // ops_price ppm
    u64le(c.target),      // target batch height
  );
}
function callSighash(c) { return taggedHash256('Cube/sighash/entry/call', encodeCallSBE(c)); }
function blsSign(secp32, sighash32) {
  const Q = bls.G2.hashToCurve(sighash32, { DST: enc.encode('Cube/bls/message') });
  return Q.multiply(blsScalar(secp32)).toBytes(); // 96 bytes
}

// ---------- API ----------
async function api(path, body) {
  const opt = body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {};
  const r = await fetch(path, opt);
  return r.json();
}

// ---------- identity (per tab) ----------
let ME = JSON.parse(sessionStorage.getItem('cube_player') || 'null');
function saveMe() { sessionStorage.setItem('cube_player', JSON.stringify(ME)); }

async function ensureFunded() {
  if (!ME) { ME = newIdentity(); saveMe(); }
  const res = await api('/api/faucet', { account_key: ME.accountKey, bls_key: ME.blsKey });
  ME.registeryIndex = res.registery_index;
  saveMe();
  return res;
}

async function buildAndSendCall(methodIndex, calldata) {
  const st = await api('/api/state', null);
  const c = {
    accountKey: ME.accountKey,
    registeryIndex: ME.registeryIndex,
    blsKey: ME.blsKey,
    contractId: st.contract_id,
    contractRegisteryIndex: st.contract_registery_index,
    methodIndex,
    calldata,
    opsPrice: 100,
    target: st.batch_height_tip + 1,
  };
  const sighash = callSighash(c);
  const sig = blsSign(fromHex(ME.secp), sighash);
  return api('/api/call', {
    account_key: c.accountKey,
    registery_index: c.registeryIndex,
    bls_key: c.blsKey,
    method_index: methodIndex,
    calldata,
    ops_price: 100,
    target: c.target,
    bls_signature: hx(sig),
  });
}

// ---------- UI ----------
const $ = (id) => document.getElementById(id);
function short(h) { return h ? h.slice(0, 8) + '…' + h.slice(-6) : ''; }
function flash(msg, kind) {
  const el = $('log');
  const d = document.createElement('div');
  d.className = 'logline ' + (kind || '');
  d.textContent = msg;
  el.prepend(d);
}

async function refresh() {
  const st = await api('/api/state?account=' + ME.accountKey, null);
  $('pot').textContent = st.treasury;
  $('entries').textContent = `${st.n % st.round_size} / ${st.round_size}`;
  $('total').textContent = st.n;
  $('mybal').textContent = (st.account && st.account.balance != null) ? st.account.balance : 0;
  const armed = st.armed === 1;
  $('drawbtn').disabled = !armed;
  $('armed').textContent = armed ? 'YES — ready to draw!' : 'no';
  $('armed').className = armed ? 'on' : '';
  if (st.last_winner) $('winner').textContent = short(st.last_winner) + '  (won ' + st.payout + ')';
  return st;
}

async function doEnter() {
  $('enterbtn').disabled = true;
  flash('Signing entry in-browser (BLS)…');
  try {
    const r = await buildAndSendCall(0, [{ type: 'payable', value: 10000 }]);
    if (r.ok) flash('Entered! paid 10000 in.', 'ok'); else flash('Enter failed: ' + (r.error || JSON.stringify(r)), 'err');
  } catch (e) { flash('Enter error: ' + e.message, 'err'); }
  await refresh();
  $('enterbtn').disabled = false;
}

async function doDraw() {
  $('drawbtn').disabled = true;
  flash('Signing draw in-browser (BLS)…');
  try {
    const r = await buildAndSendCall(1, []);
    if (r.ok) flash('Draw complete! winner: ' + short(r.winner || '') + (r.won ? '  (you won ' + r.payout + '!)' : ''), 'ok');
    else flash('Draw failed: ' + (r.error || JSON.stringify(r)), 'err');
  } catch (e) { flash('Draw error: ' + e.message, 'err'); }
  await refresh();
}

async function newPlayer() {
  ME = newIdentity(); saveMe();
  await ensureFunded();
  $('me').textContent = short(ME.accountKey);
  flash('New player ' + short(ME.accountKey) + ' funded.', 'ok');
  await refresh();
}

async function main() {
  $('me').textContent = '…';
  await ensureFunded();
  $('me').textContent = short(ME.accountKey);
  $('enterbtn').onclick = doEnter;
  $('drawbtn').onclick = doDraw;
  $('newbtn').onclick = newPlayer;
  flash('Welcome, player ' + short(ME.accountKey) + '. Keys generated & signed in your browser.', 'ok');
  await refresh();
  setInterval(refresh, 2500);
}

main();
