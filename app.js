'use strict';

/* ============================================================================
   BLAKE2b (RFC 7693), implementazione autonoma via BigInt — verificata byte per
   byte contro hashlib.blake2b di Python su piu' vettori di test, incluso un
   input multi-blocco. Nessuna dipendenza CDN per questa parte: elimina
   l'ambiguita' sul nome della funzione esportata da librerie di terze parti.
   Supporta solo hashing non-keyed, che e' tutto cio' che serve qui.
   ============================================================================ */

const BLAKE2B_MASK64 = (1n << 64n) - 1n;

const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const BLAKE2B_SIGMA = [
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
  [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
  [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
  [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
  [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
  [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
  [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
  [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
  [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
  [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
];

function blake2bRotr(x, n) {
  x &= BLAKE2B_MASK64;
  return ((x >> n) | (x << (64n - n))) & BLAKE2B_MASK64;
}

function blake2bCompress(h, block, t, isLast) {
  const m = new Array(16);
  for (let i = 0; i < 16; i++) {
    let w = 0n;
    for (let j = 0; j < 8; j++) w |= BigInt(block[i * 8 + j]) << BigInt(j * 8);
    m[i] = w;
  }

  const v = new Array(16);
  for (let i = 0; i < 8; i++) v[i] = h[i];
  for (let i = 0; i < 8; i++) v[8 + i] = BLAKE2B_IV[i];

  v[12] ^= (t & BLAKE2B_MASK64);
  v[13] ^= 0n;
  if (isLast) v[14] = (~v[14]) & BLAKE2B_MASK64;

  function G(a, b, c, d, x, y) {
    v[a] = (v[a] + v[b] + x) & BLAKE2B_MASK64;
    v[d] = blake2bRotr(v[d] ^ v[a], 32n);
    v[c] = (v[c] + v[d]) & BLAKE2B_MASK64;
    v[b] = blake2bRotr(v[b] ^ v[c], 24n);
    v[a] = (v[a] + v[b] + y) & BLAKE2B_MASK64;
    v[d] = blake2bRotr(v[d] ^ v[a], 16n);
    v[c] = (v[c] + v[d]) & BLAKE2B_MASK64;
    v[b] = blake2bRotr(v[b] ^ v[c], 63n);
  }

  for (let round = 0; round < 12; round++) {
    const s = BLAKE2B_SIGMA[round % 10];
    G(0, 4, 8, 12, m[s[0]], m[s[1]]);
    G(1, 5, 9, 13, m[s[2]], m[s[3]]);
    G(2, 6, 10, 14, m[s[4]], m[s[5]]);
    G(3, 7, 11, 15, m[s[6]], m[s[7]]);
    G(0, 5, 10, 15, m[s[8]], m[s[9]]);
    G(1, 6, 11, 12, m[s[10]], m[s[11]]);
    G(2, 7, 8, 13, m[s[12]], m[s[13]]);
    G(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }

  for (let i = 0; i < 8; i++) h[i] = (h[i] ^ v[i] ^ v[i + 8]) & BLAKE2B_MASK64;
}

// blake2b(input: Uint8Array, outLen: number) -> Uint8Array(outLen)
function blake2b(input, outLen) {
  outLen = outLen || 64;
  const h = BLAKE2B_IV.slice();
  h[0] = (h[0] ^ 0x01010000n ^ BigInt(outLen)) & BLAKE2B_MASK64;

  const blockSize = 128;
  const totalLen = input.length;
  const numBlocks = totalLen === 0 ? 1 : Math.ceil(totalLen / blockSize);
  let byteCounter = 0n;

  for (let b = 0; b < numBlocks; b++) {
    const isLast = (b === numBlocks - 1);
    const start = b * blockSize;
    const end = Math.min(start + blockSize, totalLen);
    const block = new Uint8Array(blockSize);
    block.set(input.subarray(start, end));
    byteCounter += BigInt(end - start);
    blake2bCompress(h, block, byteCounter, isLast);
  }

  const out = new Uint8Array(outLen);
  for (let i = 0; i < outLen; i++) {
    const word = h[Math.floor(i / 8)];
    out[i] = Number((word >> BigInt((i % 8) * 8)) & 0xffn);
  }
  return out;
}

/* ============================================================================
   Deve rispecchiare ESATTAMENTE gli UUID e il formato dei pacchetti del
   firmware (ble_service.cpp / crypto.cpp / chat_protocol.cpp).
   ============================================================================ */

const SERVICE_UUID           = '5f1a1e00-45c2-4b6e-9f0a-8e2c9a5b0001';
const CHAR_NODE_PUBKEY_UUID  = '5f1a1e00-45c2-4b6e-9f0a-8e2c9a5b0002';
const CHAR_PHONE_PUBKEY_UUID = '5f1a1e00-45c2-4b6e-9f0a-8e2c9a5b0003';
const CHAR_CONFIRM_UUID      = '5f1a1e00-45c2-4b6e-9f0a-8e2c9a5b0004';
const CHAR_SESSION_UUID      = '5f1a1e00-45c2-4b6e-9f0a-8e2c9a5b0005';
const CHAR_CHAT_TX_UUID      = '5f1a1e00-45c2-4b6e-9f0a-8e2c9a5b0006';
const CHAR_CHAT_RX_UUID      = '5f1a1e00-45c2-4b6e-9f0a-8e2c9a5b0007';
const CHAR_STATUS_UUID       = '5f1a1e00-45c2-4b6e-9f0a-8e2c9a5b0008';
const CHAR_CONFIG_SF_UUID    = '5f1a1e00-45c2-4b6e-9f0a-8e2c9a5b0009';
const CHAR_NICKNAME_UUID     = '5f1a1e00-45c2-4b6e-9f0a-8e2c9a5b000a';

/* ============================================================================
   Storage locale (persistente sul telefono, sopravvive alla chiusura del browser)
   ============================================================================ */

function b64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function unb64(str) { return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0))); }

function getOrCreatePhoneKeypair() {
  const stored = localStorage.getItem('phone_priv');
  if (stored) {
    const priv = unb64(stored);
    const pub = nacl.scalarMult.base(priv);
    return { priv, pub };
  }
  const priv = nacl.randomBytes(32);
  const pub = nacl.scalarMult.base(priv);
  localStorage.setItem('phone_priv', b64(priv));
  return { priv, pub };
}

function getTrustedNodePub() {
  const s = localStorage.getItem('trusted_node_pub');
  return s ? unb64(s) : null;
}
function setTrustedNodePub(pub) { localStorage.setItem('trusted_node_pub', b64(pub)); }
function forgetTrustedNode() { localStorage.removeItem('trusted_node_pub'); }

function getNickname() { return localStorage.getItem('nickname') || ''; }
function setNicknameLocal(n) { localStorage.setItem('nickname', n); }

/* ============================================================================
   Crypto — deve produrre BYTE PER BYTE lo stesso risultato del firmware
   ============================================================================ */

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// replica esatta di kdf() nel firmware: BLAKE2b a 64 byte, poi tronca a outLen
// (NON e' equivalente a chiedere a blake2b un output nativo di outLen byte)
function kdf(outLen, a, b, label) {
  const labelBytes = new TextEncoder().encode(label);
  const msg = concatBytes(a, b, labelBytes);
  const hash64 = blake2b(msg, 64); // Uint8Array(64)
  return hash64.slice(0, outLen);
}

function confirmCodeFrom(pubA, pubB, shared) {
  const out = kdf(8, pubA, pubB, 'confirm-code|');
  let v = 0;
  for (let i = 0; i < 4; i++) v = (v * 256 + out[i]) >>> 0;
  return v % 1000000;
}

const NONCE_LEN = 12;
const TAG_LEN = 16;

async function importAesKey(keyBytes) {
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// pacchetto: [nonce 12B][ciphertext][tag 16B] — stesso formato del firmware
async function aesEncrypt(keyBytes, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const key = await importAesKey(keyBytes);
  const ctAndTag = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: TAG_LEN * 8 }, key, plaintext)
  );
  return concatBytes(nonce, ctAndTag);
}

async function aesDecrypt(keyBytes, packet) {
  if (packet.length < NONCE_LEN + TAG_LEN) throw new Error('pacchetto troppo corto');
  const nonce = packet.slice(0, NONCE_LEN);
  const ctAndTag = packet.slice(NONCE_LEN);
  const key = await importAesKey(keyBytes);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: TAG_LEN * 8 }, key, ctAndTag);
  return new Uint8Array(plain);
}

/* ============================================================================
   Parsing pacchetto chat (formato definito in chat_protocol.cpp lato firmware,
   ma qui arriva GIA' decifrato dal nodo: [rssi i8][snr i8][nick_len][nick][text])
   ============================================================================ */

function parseIncomingChat(plain) {
  let off = 0;
  const rssiRaw = plain[off++]; const rssi = rssiRaw > 127 ? rssiRaw - 256 : rssiRaw;
  const snrRaw = plain[off++];  const snr = snrRaw > 127 ? snrRaw - 256 : snrRaw;
  const nickLen = plain[off++];
  const nickname = new TextDecoder().decode(plain.slice(off, off + nickLen)); off += nickLen;
  const text = new TextDecoder().decode(plain.slice(off));
  return { rssi, snr, nickname, text };
}

/* ============================================================================
   Posizione GPS — viaggia come un normale messaggio di chat con un prefisso
   riconoscibile, cifrato/instradato esattamente come il testo: nessuna modifica
   al firmware necessaria. La PWA lo intercetta prima di mostrarlo come chat.
   ============================================================================ */

const GEO_PREFIX = 'GEO:';
const POSITION_BROADCAST_INTERVAL_MS = 45000; // non ad ogni variazione: rispetta il duty cycle

function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = d => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

function bearingDeg(lat1, lon1, lat2, lon2) {
  const toRad = d => d * Math.PI / 180;
  const toDeg = r => r * 180 / Math.PI;
  const y = Math.sin(toRad(lon2 - lon1)) * Math.cos(toRad(lat2));
  const x = Math.cos(toRad(lat1)) * Math.sin(toRad(lat2)) - Math.sin(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.cos(toRad(lon2 - lon1));
  return (toDeg(Math.atan2(y, x)) + 360) % 360;
}

function formatDistance(m) {
  return m < 1000 ? Math.round(m) + ' m' : (m / 1000).toFixed(1) + ' km';
}

function loadShareLocationPref() { return localStorage.getItem('shareLocation') === '1'; }
function setShareLocationPref(v) { localStorage.setItem('shareLocation', v ? '1' : '0'); }

function initGeolocation() {
  if (!navigator.geolocation || state.geoWatchId != null) return;
  state.geoWatchId = navigator.geolocation.watchPosition(
    (pos) => {
      state.myPosition = { lat: pos.coords.latitude, lon: pos.coords.longitude };
      document.getElementById('geo-warning').style.display = 'none';
      refreshMapViews();
    },
    (err) => {
      const w = document.getElementById('geo-warning');
      w.style.display = 'block';
      w.textContent = 'Posizione non disponibile: ' + err.message;
    },
    { enableHighAccuracy: true, maximumAge: 15000, timeout: 20000 }
  );
}

function startPositionBroadcast() {
  if (state.positionBroadcastTimer) return;
  state.positionBroadcastTimer = setInterval(() => {
    if (state.shareLocation && state.myPosition) {
      const { lat, lon } = state.myPosition;
      sendChatText(GEO_PREFIX + lat.toFixed(5) + ',' + lon.toFixed(5), { visible: false });
    }
  }, POSITION_BROADCAST_INTERVAL_MS);
}
function stopPositionBroadcast() {
  if (state.positionBroadcastTimer) { clearInterval(state.positionBroadcastTimer); state.positionBroadcastTimer = null; }
}

function handleIncomingPosition(msg) {
  const parts = msg.text.slice(GEO_PREFIX.length).split(',');
  const lat = parseFloat(parts[0]);
  const lon = parseFloat(parts[1]);
  if (Number.isNaN(lat) || Number.isNaN(lon)) return;

  state.peersSeen.add(msg.nickname);
  document.getElementById('meta-peers').textContent = state.peersSeen.size;

  state.positions.set(msg.nickname, { lat, lon, rssi: msg.rssi, snr: msg.snr, lastSeen: Date.now() });
  refreshMapViews();
}

/* ============================================================================
   Stato applicazione
   ============================================================================ */

const state = {
  device: null, server: null, service: null,
  chNodePub: null, chPhonePub: null, chConfirm: null, chSession: null,
  chChatTx: null, chChatRx: null, chStatus: null, chConfigSf: null, chNickname: null,
  myKeys: null,
  nodePub: null,
  sharedSecret: null,
  sessionKey: null,
  sessionSalt: null,
  paired: false,
  peersSeen: new Set(),
  positions: new Map(),        // nickname -> {lat, lon, rssi, snr, lastSeen}
  myPosition: null,
  geoWatchId: null,
  shareLocation: loadShareLocationPref(),
  positionBroadcastTimer: null,
  mapMode: 'radar',
};

/* ============================================================================
   UI helpers
   ============================================================================ */

const screens = {
  connect: document.getElementById('screen-connect'),
  pair: document.getElementById('screen-pair'),
  chat: document.getElementById('screen-chat'),
  map: document.getElementById('screen-map'),
};
function showScreen(name) {
  Object.values(screens).forEach(s => s.classList.remove('active'));
  screens[name].classList.add('active');
}
function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2200);
}

function signalClass(rssi) {
  if (rssi > -90) return 'good';
  if (rssi > -110) return 'mid';
  return 'weak';
}

const messagesEl = document.getElementById('messages');
function addMessageToUI({ own, nick, text, rssi, snr, status }) {
  const wrap = document.createElement('div');
  wrap.className = 'msg ' + (own ? 'own' : 'other');

  const meta = document.createElement('div');
  meta.className = 'msg-meta';
  if (own) {
    meta.innerHTML = `<span class="msg-status">${status || ''}</span>`;
  } else {
    const cls = signalClass(rssi);
    meta.innerHTML = `
      <span class="msg-nick">${escapeHtml(nick)}</span>
      <span class="signal ${cls}"><i></i><i></i><i></i><i></i></span>
      <span>${rssi}dBm · SNR ${snr}dB</span>
    `;
  }

  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.textContent = text;

  wrap.appendChild(meta);
  wrap.appendChild(bubble);
  messagesEl.appendChild(wrap);
  messagesEl.scrollTop = messagesEl.scrollHeight;
  return wrap;
}
function escapeHtml(s) { return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

/* ============================================================================
   Connessione BLE
   ============================================================================ */

document.getElementById('btn-scan').addEventListener('click', connectToNode);

async function connectToNode() {
  if (!navigator.bluetooth) {
    document.getElementById('bt-warning').style.display = 'block';
    return;
  }

  const radar = document.getElementById('radar');
  const status = document.getElementById('connect-status');
  radar.classList.add('scanning');
  status.textContent = 'Ricerca dispositivi BLE...';

  try {
    state.device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [SERVICE_UUID] }],
      optionalServices: [SERVICE_UUID],
    });
    state.device.addEventListener('gattserverdisconnected', onDisconnected);

    status.textContent = 'Connessione a ' + (state.device.name || 'nodo') + '...';
    state.server = await state.device.gatt.connect();
    state.service = await state.server.getPrimaryService(SERVICE_UUID);

    state.chNodePub  = await state.service.getCharacteristic(CHAR_NODE_PUBKEY_UUID);
    state.chPhonePub = await state.service.getCharacteristic(CHAR_PHONE_PUBKEY_UUID);
    state.chConfirm  = await state.service.getCharacteristic(CHAR_CONFIRM_UUID);
    state.chSession  = await state.service.getCharacteristic(CHAR_SESSION_UUID);
    state.chChatTx   = await state.service.getCharacteristic(CHAR_CHAT_TX_UUID);
    state.chChatRx   = await state.service.getCharacteristic(CHAR_CHAT_RX_UUID);
    state.chStatus   = await state.service.getCharacteristic(CHAR_STATUS_UUID);
    state.chConfigSf = await state.service.getCharacteristic(CHAR_CONFIG_SF_UUID);
    state.chNickname = await state.service.getCharacteristic(CHAR_NICKNAME_UUID);

    state.myKeys = getOrCreatePhoneKeypair();

    // legge la pubkey del nodo
    const nodePubVal = await state.chNodePub.readValue();
    state.nodePub = new Uint8Array(nodePubVal.buffer);

    // sottoscrizioni alle notify (va fatto prima di scrivere la pubkey, cosi'
    // non perdiamo la notifica del salt che il nodo manda in risposta)
    await state.chSession.startNotifications();
    state.chSession.addEventListener('characteristicvaluechanged', onSessionSaltChanged);

    await state.chChatRx.startNotifications();
    state.chChatRx.addEventListener('characteristicvaluechanged', onChatMessageReceived);

    await state.chStatus.startNotifications();
    state.chStatus.addEventListener('characteristicvaluechanged', onStatusNotification);

    // calcola il segreto condiviso (sempre lo stesso finche' priv/nodePub non cambiano)
    state.sharedSecret = nacl.scalarMult(state.myKeys.priv, state.nodePub);

    // il nodo genera un salt fresco esattamente quando riceve la nostra pubkey
    // e lo notifica subito: aspettiamo QUELLA notifica specifica invece di
    // leggerne una eventualmente letta in anticipo, per essere certi di usare
    // lo stesso identico salt che usa il nodo nello stesso istante
    const saltPromise = new Promise((resolve) => { state._onNextSalt = resolve; });

    await state.chPhonePub.writeValue(state.myKeys.pub);
    state.sessionSalt = await saltPromise;
    await recomputeSessionKey();

    const trusted = getTrustedNodePub();

    radar.classList.remove('scanning');

    if (trusted && bytesEqual(trusted, state.nodePub)) {
      // gia' fidato: nessuna ceremony, si passa direttamente alla chat
      state.paired = true;
      enterChat();
    } else if (trusted && !bytesEqual(trusted, state.nodePub)) {
      status.textContent = 'Attenzione: questo non è il nodo fidato in precedenza.';
      toast('Nodo diverso da quello fidato in precedenza');
      showPairingScreen();
    } else {
      showPairingScreen();
    }
  } catch (err) {
    console.error(err);
    radar.classList.remove('scanning');
    status.textContent = 'Connessione fallita: ' + err.message;
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function toHexDbg(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function recomputeSessionKey() {
  state.sessionKey = kdf(32, state.sharedSecret, state.sessionSalt, 'session-key|');
}

function onSessionSaltChanged(event) {
  const salt = new Uint8Array(event.target.value.buffer);
  state.sessionSalt = salt;

  if (state._onNextSalt) {
    // qualcuno sta aspettando specificamente questo salt (pairing/auth in corso)
    const resolve = state._onNextSalt;
    state._onNextSalt = null;
    resolve(salt);
  } else {
    // notifica "spontanea": e' una rotazione periodica della chiave di sessione
    // lato nodo, ricalcoliamo subito la nostra per restare allineati
    recomputeSessionKey();
  }
}

function onDisconnected() {
  stopPositionBroadcast();
  toast('Disconnesso dal nodo');
  showScreen('connect');
  document.getElementById('connect-status').textContent = '';
}

/* ============================================================================
   Pairing
   ============================================================================ */

function showPairingScreen() {
  const code = confirmCodeFrom(state.nodePub, state.myKeys.pub, state.sharedSecret);
  document.getElementById('pair-code').textContent = String(code).padStart(6, '0');
  showScreen('pair');
}

document.getElementById('btn-confirm').addEventListener('click', async () => {
  await state.chConfirm.writeValue(new Uint8Array([0x01]));
  setTrustedNodePub(state.nodePub);
  state.paired = true;
  toast('Pairing completato');
  enterChat();
});

document.getElementById('btn-reject').addEventListener('click', async () => {
  try { await state.chConfirm.writeValue(new Uint8Array([0x00])); } catch (e) {}
  toast('Pairing annullato');
  if (state.device && state.device.gatt.connected) state.device.gatt.disconnect();
  showScreen('connect');
});

/* ============================================================================
   Chat
   ============================================================================ */

async function enterChat() {
  document.getElementById('chat-nodename').textContent = state.device.name || 'Nodo';
  document.getElementById('conn-sub').textContent = 'connesso';

  // carica SF e nickname correnti dal nodo
  try {
    const sfVal = await state.chConfigSf.readValue();
    const sf = new Uint8Array(sfVal.buffer)[0];
    document.getElementById('meta-sf').textContent = sf;
    selectSfOption(sf);
  } catch (e) {}

  try {
    const nickVal = await state.chNickname.readValue();
    const nick = new TextDecoder().decode(nickVal.buffer);
    document.getElementById('nick-input').value = nick;
  } catch (e) {}

  // riflette il toggle "condividi posizione" salvato e riavvia il broadcast se attivo
  document.getElementById('switch-share-location').classList.toggle('on', state.shareLocation);
  if (state.shareLocation) startPositionBroadcast();

  updateTabActive('chat');
  showScreen('chat');
}

document.getElementById('btn-send').addEventListener('click', sendMessage);
document.getElementById('msg-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') sendMessage();
});

async function sendMessage() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  await sendChatText(text, { visible: true });
}

// riusata anche per gli aggiornamenti di posizione (visible:false = non compare in chat)
async function sendChatText(text, opts) {
  const visible = opts && opts.visible;
  if (!text || !state.sessionKey) return false;

  let el = null;
  if (visible) el = addMessageToUI({ own: true, text, status: 'invio...' });

  try {
    const plaintext = new TextEncoder().encode(text);
    const packet = await aesEncrypt(state.sessionKey, plaintext);
    await state.chChatTx.writeValue(packet);

    if (visible) {
      el.dataset.pending = '1';
      el._statusEl = el.querySelector('.msg-status');
      el._statusEl.textContent = 'in coda...';
      state._lastSentEl = el;

      // rete di sicurezza: se l'ack non arriva entro pochi secondi, segnalalo
      // invece di lasciare il messaggio bloccato su "in coda..." senza spiegazione
      setTimeout(() => {
        if (el._statusEl.textContent === 'in coda...') {
          el._statusEl.textContent = '⚠ nessuna risposta dal nodo';
        }
      }, 6000);
    }
    return true;
  } catch (err) {
    if (visible) el.querySelector('.msg-status').textContent = '✗ errore invio';
    return false;
  }
}

function onStatusNotification(event) {
  const msg = new TextDecoder().decode(event.target.value.buffer);
  if (state._lastSentEl && state._lastSentEl._statusEl) {
    if (msg === 'sent') state._lastSentEl._statusEl.textContent = '✓ inviato';
    else if (msg === 'duty_cycle_blocked') state._lastSentEl._statusEl.textContent = '⏸ limite duty cycle';
    else state._lastSentEl._statusEl.textContent = msg;
  }
}

async function onChatMessageReceived(event) {
  try {
    const packet = new Uint8Array(event.target.value.buffer);
    const plain = await aesDecrypt(state.sessionKey, packet);
    const msg = parseIncomingChat(plain);

    if (msg.text.startsWith(GEO_PREFIX)) {
      handleIncomingPosition(msg);
      return;
    }

    state.peersSeen.add(msg.nickname);
    document.getElementById('meta-peers').textContent = state.peersSeen.size;

    addMessageToUI({ own: false, nick: msg.nickname, text: msg.text, rssi: msg.rssi, snr: msg.snr });
  } catch (err) {
    console.error('Messaggio ricevuto non decifrabile', err);
  }
}

/* ============================================================================
   Impostazioni
   ============================================================================ */

const overlay = document.getElementById('settings-overlay');
document.getElementById('btn-settings').addEventListener('click', () => overlay.classList.add('active'));
document.getElementById('btn-settings-map').addEventListener('click', () => overlay.classList.add('active'));
overlay.addEventListener('click', e => { if (e.target === overlay) overlay.classList.remove('active'); });

function selectSfOption(sf) {
  document.querySelectorAll('.sf-opt').forEach(o => {
    o.classList.toggle('selected', o.dataset.sf === String(sf));
  });
}

document.querySelectorAll('.sf-opt').forEach(opt => {
  opt.addEventListener('click', async () => {
    const sf = parseInt(opt.dataset.sf, 10);
    try {
      await state.chConfigSf.writeValue(new Uint8Array([sf]));
      selectSfOption(sf);
      document.getElementById('meta-sf').textContent = sf;
      toast('Spreading factor impostato a SF' + sf);
    } catch (err) {
      toast('Errore impostando SF' + sf);
    }
  });
});

document.getElementById('nick-input').addEventListener('change', async (e) => {
  const nick = e.target.value.trim();
  if (!nick) return;
  try {
    await state.chNickname.writeValue(new TextEncoder().encode(nick));
    setNicknameLocal(nick);
    toast('Nickname salvato');
  } catch (err) {
    toast('Errore salvando il nickname');
  }
});

document.getElementById('toggle-share-location').addEventListener('click', () => {
  state.shareLocation = !state.shareLocation;
  setShareLocationPref(state.shareLocation);
  document.getElementById('switch-share-location').classList.toggle('on', state.shareLocation);

  if (state.shareLocation) {
    initGeolocation();
    startPositionBroadcast();
    toast('Condivisione posizione attivata');
  } else {
    stopPositionBroadcast();
    toast('Condivisione posizione disattivata');
  }
});

document.getElementById('btn-forget').addEventListener('click', () => {
  forgetTrustedNode();
  overlay.classList.remove('active');
  stopPositionBroadcast();
  if (state.device && state.device.gatt.connected) state.device.gatt.disconnect();
  showScreen('connect');
  toast('Nodo dimenticato (ricorda di dimenticarlo anche premendo a lungo il pulsante sul nodo)');
});

document.getElementById('btn-disconnect').addEventListener('click', () => {
  overlay.classList.remove('active');
  stopPositionBroadcast();
  if (state.device && state.device.gatt.connected) state.device.gatt.disconnect();
});

/* ============================================================================
   Tab bar (Chat / Mappa)
   ============================================================================ */

function updateTabActive(view) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.view === view));
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const view = btn.dataset.view;
    updateTabActive(view);
    showScreen(view);
    if (view === 'map') {
      initGeolocation(); // vedere se stessi sul radar non richiede di condividere la posizione
      if (state.mapMode === 'tiles') ensureLeafletMap();
      refreshMapViews();
    }
  });
});

document.querySelectorAll('.map-mode-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const mode = btn.dataset.mapmode;
    document.querySelectorAll('.map-mode-btn').forEach(b => b.classList.toggle('active', b === btn));
    document.getElementById('radar-view').classList.toggle('active', mode === 'radar');
    document.getElementById('tiles-view').classList.toggle('active', mode === 'tiles');
    state.mapMode = mode;
    if (mode === 'tiles') { ensureLeafletMap(); refreshLeafletMarkers(); }
    else renderRadar();
  });
});

/* ============================================================================
   Vista Radar tattico — nessuna mappa di sfondo, solo distanza/direzione
   relativa: funziona sempre, anche completamente offline.
   ============================================================================ */

function renderRadar() {
  const svg = document.getElementById('radar-svg');
  const legend = document.getElementById('radar-legend');
  const NS = 'http://www.w3.org/2000/svg';
  svg.innerHTML = '';
  const cx = 160, cy = 160, maxR = 140;

  const withDist = [];
  let maxDist = 100; // floor, evita uno zoom assurdo con nodi vicinissimi
  if (state.myPosition) {
    for (const [nick, p] of state.positions.entries()) {
      const d = haversineDistance(state.myPosition.lat, state.myPosition.lon, p.lat, p.lon);
      const b = bearingDeg(state.myPosition.lat, state.myPosition.lon, p.lat, p.lon);
      withDist.push({ nick, dist: d, bearing: b, lastSeen: p.lastSeen });
      if (d > maxDist) maxDist = d;
    }
  }
  maxDist *= 1.15;

  [1 / 3, 2 / 3, 1].forEach(f => {
    const r = maxR * f;
    const circle = document.createElementNS(NS, 'circle');
    circle.setAttribute('cx', cx); circle.setAttribute('cy', cy); circle.setAttribute('r', r);
    circle.setAttribute('class', 'radar-ring');
    svg.appendChild(circle);
    const label = document.createElementNS(NS, 'text');
    label.setAttribute('x', cx + 4); label.setAttribute('y', cy - r - 2);
    label.setAttribute('class', 'radar-ring-label');
    label.textContent = formatDistance(maxDist * f);
    svg.appendChild(label);
  });

  [[cx - maxR, cy, cx + maxR, cy], [cx, cy - maxR, cx, cy + maxR]].forEach(([x1, y1, x2, y2]) => {
    const line = document.createElementNS(NS, 'line');
    line.setAttribute('x1', x1); line.setAttribute('y1', y1);
    line.setAttribute('x2', x2); line.setAttribute('y2', y2);
    line.setAttribute('class', 'radar-crosshair');
    svg.appendChild(line);
  });

  const nLabel = document.createElementNS(NS, 'text');
  nLabel.setAttribute('x', cx - 4); nLabel.setAttribute('y', cy - maxR - 6);
  nLabel.setAttribute('class', 'radar-ring-label');
  nLabel.textContent = 'N';
  svg.appendChild(nLabel);

  const self = document.createElementNS(NS, 'rect');
  self.setAttribute('x', cx - 6); self.setAttribute('y', cy - 6);
  self.setAttribute('width', 12); self.setAttribute('height', 12);
  self.setAttribute('transform', `rotate(45 ${cx} ${cy})`);
  self.setAttribute('class', 'radar-self');
  svg.appendChild(self);

  withDist.forEach(p => {
    const angleRad = (p.bearing - 90) * Math.PI / 180; // 0deg=N in alto
    const r = (p.dist / maxDist) * maxR;
    const x = cx + r * Math.cos(angleRad);
    const y = cy + r * Math.sin(angleRad);

    const ageMin = (Date.now() - p.lastSeen) / 60000;
    const color = ageMin < 5 ? 'var(--accent)' : ageMin < 20 ? 'var(--warn)' : 'var(--muted)';

    const dot = document.createElementNS(NS, 'rect');
    dot.setAttribute('x', x - 5); dot.setAttribute('y', y - 5);
    dot.setAttribute('width', 10); dot.setAttribute('height', 10);
    dot.setAttribute('transform', `rotate(45 ${x} ${y})`);
    dot.setAttribute('fill', 'var(--bg)');
    dot.setAttribute('stroke', color);
    dot.setAttribute('class', 'radar-peer-dot');
    svg.appendChild(dot);

    const label = document.createElementNS(NS, 'text');
    label.setAttribute('x', x + 9); label.setAttribute('y', y + 3);
    label.setAttribute('class', 'radar-peer-label');
    label.textContent = `${p.nick} · ${formatDistance(p.dist)}`;
    svg.appendChild(label);
  });

  legend.textContent = state.myPosition
    ? `${withDist.length} nodi con posizione nota`
    : 'In attesa del GPS del telefono... (consenti l\'accesso quando richiesto)';

  document.getElementById('map-peers-sub').textContent = `${withDist.length} nodi con posizione`;
}

/* ============================================================================
   Vista Mappa — Leaflet con un layer offline "a griglia" (nessuna tile da
   internet). Per usare tile reali, scarica un set per la tua zona (es. con
   QGIS o un tile downloader offline) e sostituisci il layer con:
     L.tileLayer('tiles/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(leafletMap)
   ============================================================================ */

let leafletMap = null;
const leafletMarkers = new Map();

function ensureLeafletMap() {
  if (leafletMap) { setTimeout(() => leafletMap.invalidateSize(), 50); return; }
  if (typeof L === 'undefined') return;

  const center = state.myPosition ? [state.myPosition.lat, state.myPosition.lon] : [0, 0];
  leafletMap = L.map('leaflet-map', { attributionControl: false }).setView(center, state.myPosition ? 15 : 2);

  const GraticuleLayer = L.GridLayer.extend({
    createTile: function (coords) {
      const tile = document.createElement('canvas');
      const size = this.getTileSize();
      tile.width = size.x; tile.height = size.y;
      const ctx = tile.getContext('2d');
      ctx.fillStyle = '#1a1f1a';
      ctx.fillRect(0, 0, size.x, size.y);
      ctx.strokeStyle = '#2a2f2a';
      ctx.lineWidth = 1;
      ctx.strokeRect(0.5, 0.5, size.x - 1, size.y - 1);
      ctx.fillStyle = '#3a423a';
      ctx.font = '9px monospace';
      ctx.fillText(coords.z + '/' + coords.x + '/' + coords.y, 4, 12);
      return tile;
    }
  });
  new GraticuleLayer().addTo(leafletMap);
}

function refreshLeafletMarkers() {
  if (!leafletMap) return;

  if (state.myPosition) {
    if (!leafletMarkers.has('__self__')) {
      const icon = L.divIcon({ className: 'geo-marker self', iconSize: [16, 16] });
      leafletMarkers.set('__self__', L.marker([state.myPosition.lat, state.myPosition.lon], { icon }).addTo(leafletMap).bindPopup('Tu'));
    } else {
      leafletMarkers.get('__self__').setLatLng([state.myPosition.lat, state.myPosition.lon]);
    }
  }

  for (const [nick, p] of state.positions.entries()) {
    if (leafletMarkers.has(nick)) {
      leafletMarkers.get(nick).setLatLng([p.lat, p.lon]);
    } else {
      const icon = L.divIcon({ className: 'geo-marker', iconSize: [16, 16] });
      leafletMarkers.set(nick, L.marker([p.lat, p.lon], { icon }).addTo(leafletMap).bindPopup(nick));
    }
  }

  document.getElementById('map-peers-sub').textContent = `${state.positions.size} nodi con posizione`;
}

function refreshMapViews() {
  if (state.mapMode === 'radar') renderRadar();
  else refreshLeafletMarkers();
}

/* ============================================================================
   Service worker (funzionamento offline)
   ============================================================================ */

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch(err => console.warn('SW non registrato:', err));
  });
}

if (!navigator.bluetooth) {
  document.getElementById('bt-warning').style.display = 'block';
}
