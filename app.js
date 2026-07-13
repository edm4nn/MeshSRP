'use strict';

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
  const hash64 = blake2b(msg, null, 64); // Uint8Array(64)
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
};

/* ============================================================================
   UI helpers
   ============================================================================ */

const screens = {
  connect: document.getElementById('screen-connect'),
  pair: document.getElementById('screen-pair'),
  chat: document.getElementById('screen-chat'),
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

    // sottoscrizioni alle notify
    await state.chSession.startNotifications();
    state.chSession.addEventListener('characteristicvaluechanged', onSessionSaltChanged);
    const initialSalt = await state.chSession.readValue();
    state.sessionSalt = new Uint8Array(initialSalt.buffer);

    await state.chChatRx.startNotifications();
    state.chChatRx.addEventListener('characteristicvaluechanged', onChatMessageReceived);

    await state.chStatus.startNotifications();
    state.chStatus.addEventListener('characteristicvaluechanged', onStatusNotification);

    // calcola il segreto condiviso (sempre lo stesso finche' priv/nodePub non cambiano)
    state.sharedSecret = nacl.scalarMult(state.myKeys.priv, state.nodePub);
    recomputeSessionKey();

    // annuncia la propria pubkey al nodo (avvia la ceremony di pairing, o
    // l'autenticazione automatica se questo nodo e' gia' fidato)
    const trusted = getTrustedNodePub();
    await state.chPhonePub.writeValue(state.myKeys.pub);

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

async function recomputeSessionKey() {
  state.sessionKey = kdf(32, state.sharedSecret, state.sessionSalt, 'session-key|');
}

function onSessionSaltChanged(event) {
  state.sessionSalt = new Uint8Array(event.target.value.buffer);
  recomputeSessionKey(); // rotazione periodica lato firmware: si riallinea da sola
}

function onDisconnected() {
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

  showScreen('chat');
}

document.getElementById('btn-send').addEventListener('click', sendMessage);
document.getElementById('msg-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') sendMessage();
});

async function sendMessage() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text || !state.sessionKey) return;
  input.value = '';

  const el = addMessageToUI({ own: true, text, status: 'invio...' });

  try {
    const plaintext = new TextEncoder().encode(text);
    const packet = await aesEncrypt(state.sessionKey, plaintext);
    await state.chChatTx.writeValue(packet);
    // la conferma definitiva arriva su chStatus (onStatusNotification):
    // qui segnamo solo che e' stato scritto sul canale BLE
    el.dataset.pending = '1';
    el.querySelector('.msg-status').textContent = 'in coda...';
    el._statusEl = el.querySelector('.msg-status');
    state._lastSentEl = el;
  } catch (err) {
    el.querySelector('.msg-status').textContent = '✗ errore invio';
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

document.getElementById('btn-forget').addEventListener('click', () => {
  forgetTrustedNode();
  overlay.classList.remove('active');
  if (state.device && state.device.gatt.connected) state.device.gatt.disconnect();
  showScreen('connect');
  toast('Nodo dimenticato (ricorda di dimenticarlo anche premendo a lungo il pulsante sul nodo)');
});

document.getElementById('btn-disconnect').addEventListener('click', () => {
  overlay.classList.remove('active');
  if (state.device && state.device.gatt.connected) state.device.gatt.disconnect();
});

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
