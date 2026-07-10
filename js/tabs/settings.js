import { ble } from "../ble.js";
import { getSetting, setSetting } from "../db.js";

function setStatus(el, message, kind) {
  el.textContent = message;
  el.classList.remove("error", "ok");
  if (kind) el.classList.add(kind);
}

export async function mount(container) {
  const savedPreset = await getSetting("preset", "MEDIO");
  const savedTransport = await getSetting("transport", "AUTO");
  const lastKnownNode = await getSetting("lastKnownNode", null);

  container.innerHTML = `
    <h2>Impostazioni</h2>

    <div class="info-box" id="node-info">
      <div class="info-row"><span>Stato BLE</span><span id="info-ble">non connesso</span></div>
      <div class="info-row"><span>ID nodo</span><span id="info-id">${lastKnownNode ? lastKnownNode.id : "—"}</span></div>
      <div class="info-row"><span>Nome</span><span id="info-name">${lastKnownNode ? lastKnownNode.name : "—"}</span></div>
    </div>

    <div class="field-group">
      <div class="field-row">
        <button type="button" class="btn" id="btn-connect">Collega nodo</button>
        <button type="button" class="btn secondary" id="btn-disconnect" hidden>Disconnetti</button>
      </div>
      <div class="status-line" id="connect-status"></div>
    </div>

    <div class="field-group" id="pairing-group" hidden>
      <span class="field-label">Pairing nodo (SET_NODE_ID)</span>
      <div class="field-row">
        <input type="number" id="pair-id" placeholder="ID (0-65534)" min="0" max="65534" />
      </div>
      <div class="field-row" style="margin-top:0.5rem">
        <input type="text" id="pair-name" placeholder="Nome (max 16 caratteri)" maxlength="16" />
      </div>
      <div class="field-row" style="margin-top:0.5rem">
        <input type="text" id="pair-code" placeholder="Codice dal monitor seriale" />
      </div>
      <div class="field-row" style="margin-top:0.5rem">
        <button type="button" class="btn" id="btn-pair">Provisiona</button>
      </div>
      <div class="status-line" id="pair-status"></div>
    </div>

    <div class="field-group">
      <span class="field-label">Preset radio</span>
      <div class="pill-group" id="preset-group">
        <button type="button" class="pill" data-preset="MEDIO">MEDIO</button>
        <button type="button" class="pill" data-preset="LUNGO">LUNGO</button>
      </div>
      <div class="status-line" id="preset-status"></div>
    </div>

    <div class="field-group">
      <span class="field-label">Trasporto forzato (solo diagnostica)</span>
      <div class="pill-group" id="transport-group">
        <button type="button" class="pill" data-transport="AUTO">AUTO</button>
        <button type="button" class="pill" data-transport="LORA">LORA</button>
        <button type="button" class="pill" data-transport="ESPNOW">ESPNOW</button>
      </div>
      <div class="status-line" id="transport-status"></div>
    </div>
  `;

  const infoBle = container.querySelector("#info-ble");
  const infoId = container.querySelector("#info-id");
  const infoName = container.querySelector("#info-name");
  const btnConnect = container.querySelector("#btn-connect");
  const btnDisconnect = container.querySelector("#btn-disconnect");
  const connectStatus = container.querySelector("#connect-status");
  const pairingGroup = container.querySelector("#pairing-group");
  const pairStatus = container.querySelector("#pair-status");
  const presetStatus = container.querySelector("#preset-status");
  const transportStatus = container.querySelector("#transport-status");

  function highlightPill(groupSelector, attr, value) {
    container.querySelectorAll(`${groupSelector} .pill`).forEach((btn) => {
      const isActive = btn.dataset[attr] === value;
      btn.classList.toggle("active", isActive);
      btn.classList.toggle("warn", attr === "transport" && value !== "AUTO" && isActive);
    });
  }

  highlightPill("#preset-group", "preset", savedPreset);
  highlightPill("#transport-group", "transport", savedTransport);

  async function refreshWhoami() {
    try {
      const line = await ble.sendCommand("WHOAMI");
      const m = /^ID (\d+) (.+)$/.exec(line);
      if (m) {
        const node = { id: m[1], name: m[2] };
        infoId.textContent = node.id;
        infoName.textContent = node.name;
        await setSetting("lastKnownNode", node);
        pairingGroup.hidden = node.name !== "UNCONFIGURED";
      }
    } catch (err) {
      setStatus(connectStatus, `Errore WHOAMI: ${err.message}`, "error");
    }
  }

  function updateConnectionUi() {
    const connected = ble.connected;
    infoBle.textContent = connected ? "connesso" : "non connesso";
    infoBle.classList.toggle("connected", connected);
    btnConnect.hidden = connected;
    btnDisconnect.hidden = !connected;
    if (connected) refreshWhoami();
  }

  btnConnect.addEventListener("click", async () => {
    setStatus(connectStatus, "Apertura selezione dispositivo...", null);
    try {
      await ble.connect();
      setStatus(connectStatus, "Connesso.", "ok");
    } catch (err) {
      setStatus(connectStatus, `Connessione fallita: ${err.message}`, "error");
    }
  });

  btnDisconnect.addEventListener("click", () => {
    ble.disconnect();
  });

  container.querySelector("#btn-pair").addEventListener("click", async () => {
    const id = container.querySelector("#pair-id").value.trim();
    const name = container.querySelector("#pair-name").value.trim();
    const code = container.querySelector("#pair-code").value.trim();

    if (!id || !name || !code) {
      setStatus(pairStatus, "Compila ID, nome e codice.", "error");
      return;
    }

    setStatus(pairStatus, "Invio SET_NODE_ID...", null);
    try {
      const reply = await ble.sendCommand(`SET_NODE_ID ${id} ${name} ${code}`);
      if (reply === "OK") {
        setStatus(pairStatus, "Nodo provisionato.", "ok");
        await refreshWhoami();
      } else {
        setStatus(pairStatus, `Rifiutato dal nodo: ${reply}`, "error");
      }
    } catch (err) {
      setStatus(pairStatus, `Errore: ${err.message}`, "error");
    }
  });

  container.querySelector("#preset-group").addEventListener("click", async (ev) => {
    const btn = ev.target.closest(".pill");
    if (!btn) return;
    const preset = btn.dataset.preset;

    if (!ble.connected) {
      setStatus(presetStatus, "Collega prima il nodo.", "error");
      return;
    }

    setStatus(presetStatus, "Invio SET_PRESET...", null);
    try {
      const reply = await ble.sendCommand(`SET_PRESET ${preset}`);
      if (reply === "OK") {
        highlightPill("#preset-group", "preset", preset);
        await setSetting("preset", preset);
        setStatus(presetStatus, "Preset aggiornato.", "ok");
      } else {
        setStatus(presetStatus, `Rifiutato: ${reply}`, "error");
      }
    } catch (err) {
      setStatus(presetStatus, `Errore: ${err.message}`, "error");
    }
  });

  container.querySelector("#transport-group").addEventListener("click", async (ev) => {
    const btn = ev.target.closest(".pill");
    if (!btn) return;
    const transport = btn.dataset.transport;

    if (!ble.connected) {
      setStatus(transportStatus, "Collega prima il nodo.", "error");
      return;
    }

    setStatus(transportStatus, "Invio SET_TRANSPORT...", null);
    try {
      const reply = await ble.sendCommand(`SET_TRANSPORT ${transport}`);
      if (reply === "OK") {
        highlightPill("#transport-group", "transport", transport);
        await setSetting("transport", transport);
        window.dispatchEvent(new CustomEvent("meshsrp:transport-changed", { detail: transport }));
        setStatus(
          transportStatus,
          transport === "AUTO" ? "Trasporto: AUTO." : `MODALITÀ TEST: ${transport} (torna AUTO al riavvio del nodo).`,
          transport === "AUTO" ? "ok" : "error"
        );
      } else {
        setStatus(transportStatus, `Rifiutato: ${reply}`, "error");
      }
    } catch (err) {
      setStatus(transportStatus, `Errore: ${err.message}`, "error");
    }
  });

  const onConnected = () => {
    updateConnectionUi();
    setStatus(connectStatus, "Connesso.", "ok");
  };
  const onDisconnected = () => {
    updateConnectionUi();
    setStatus(connectStatus, "Nodo disconnesso.", "error");
  };

  ble.addEventListener("connected", onConnected);
  ble.addEventListener("disconnected", onDisconnected);

  updateConnectionUi();

  return {
    onUnmount() {
      ble.removeEventListener("connected", onConnected);
      ble.removeEventListener("disconnected", onDisconnected);
    },
  };
}
