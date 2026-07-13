# MeshSRP — PWA

## Prima di provarla: requisito HTTPS

Web Bluetooth funziona solo in un **contesto sicuro**: HTTPS, oppure `localhost`
durante lo sviluppo. Aprire `index.html` con doppio click (`file://`) **non basta**
— il Bluetooth non partirà.

Modi rapidi per ottenere un'HTTPS vero:
- **GitHub Pages**: crea un repo, carica questi file, attiva Pages nelle
  impostazioni — ottieni un URL `https://tuonome.github.io/...` gratis.
- **Netlify / Vercel**: drag-and-drop della cartella, deploy istantaneo.
- **In locale per test rapidi**: `npx serve .` e poi accedi da telefono a
  `https://<ip-del-pc>:PORTA` con un certificato locale (es. tramite `mkcert`),
  oppure usa `chrome://flags/#unsafely-treat-insecure-origin-as-secure`
  sul telefono per un dominio interno solo in fase di test.

## Come installarla sul telefono

1. Apri l'URL HTTPS con **Chrome su Android**.
2. Chrome mostrerà il prompt "Aggiungi a schermata Home" (o menu ⋮ →
   "Installa app"). Da lì diventa un'icona come un'app nativa.
3. Una volta aperta almeno una volta, il service worker mette in cache tutto
   il necessario: da quel momento si apre anche **senza connessione internet**
   (la comunicazione con il nodo resta comunque solo via Bluetooth locale).

## Limite importante: solo Android

**Su iPhone non funzionerà per la parte Bluetooth.** Non è un bug di questa
app: nessun browser su iOS supporta Web Bluetooth, perché tutti (Chrome,
Firefox, ecc. inclusi) sono obbligati da Apple a usare il motore WebKit di
Safari, che non lo implementa. Puoi comunque installarla su iPhone (l'icona
comparirà), ma senza poter collegarti al nodo. Se ti serve iOS, il passo
successivo è avvolgere questo stesso codice con **Capacitor**, sostituendo
Web Bluetooth con un plugin BLE nativo.

## Verso un'app nativa (quando vorrai farlo)

Tutta la logica in `app.js` (crypto, protocollo, stato) non dipende dal DOM
in modo stretto: portarla dentro un progetto Capacitor o React Native
richiederà soprattutto riscrivere lo strato di comunicazione BLE, non la
logica di pairing/cifratura/chat, che è già isolata e riusabile.

## File del progetto

- `index.html` — struttura delle schermate
- `app.css` — stile
- `app.js` — Web Bluetooth, crypto (X25519 + BLAKE2b via librerie JS
  compatibili byte-per-byte col firmware, AES-256-GCM via WebCrypto nativa),
  logica chat
- `manifest.json` — rende l'app installabile
- `sw.js` — cache offline
- `icons/` — icone per la schermata Home

## Nota sulle librerie crypto usate

- **tweetnacl.js**: implementa X25519 (scalar multiplication su Curve25519)
  in modo standard e interoperabile con la libreria "Crypto" (Curve25519)
  usata lato firmware — stesso algoritmo, stessa clamping, chiavi compatibili.
- **BLAKE2b**: implementazione autonoma dentro `app.js` (niente dipendenza
  CDN), verificata byte per byte contro `hashlib.blake2b` di Python su più
  vettori di test — usata per derivare la chiave di sessione e il codice di
  conferma esattamente come fa il firmware.
- **AES-256-GCM**: uso l'API nativa del browser (`crypto.subtle`), non serve
  una libreria esterna — è supportata da anni su tutti i browser moderni.
