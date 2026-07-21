// Vlxchat client
// All cryptography runs here, in the browser. The passphrase and the
// derived key NEVER leave this tab. The server only ever receives the
// ciphertext + a random IV, both meaningless without the passphrase.

const enc = new TextEncoder();
const dec = new TextDecoder();

let ws = null;
let aesKey = null;
let roomCode = null;
let displayName = null;
let destructTimers = new Set();

// ---------------------------------------------------------------- crypto --

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomPassphrase() {
  const words = [
    "solyom", "hegy", "torony", "vihar", "acel", "gyanta", "kobalt", "fenyor",
    "delta", "orkan", "zafir", "kvarc", "north", "vector", "cinder", "raptor",
  ];
  const pick = () => words[Math.floor(Math.random() * words.length)];
  return `${pick()}-${pick()}-${randomHex(2)}-${pick()}`;
}

async function deriveKey(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 250000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext)
  );
  return {
    iv: btoa(String.fromCharCode(...iv)),
    ct: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
  };
}

async function decryptText(key, ivB64, ctB64) {
  const iv = Uint8Array.from(atob(ivB64), (c) => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(ctB64), (c) => c.charCodeAt(0));
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(plainBuf);
}

// -------------------------------------------------------------------- UI --

const gateView = document.getElementById("gateView");
const chatView = document.getElementById("chatView");
const messagesEl = document.getElementById("messages");
const statusLeft = document.getElementById("statusLeft");
const statusClock = document.getElementById("statusClock");
const gateError = document.getElementById("gateError");

function tick() {
  const now = new Date();
  statusClock.textContent = now.toTimeString().slice(0, 8);
}
setInterval(tick, 1000);
tick();

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
    tab.classList.add("active");
    document.querySelector(`.tab-panel[data-panel="${tab.dataset.tab}"]`).classList.remove("hidden");
    gateError.classList.add("hidden");
  });
});

const createRoomCodeEl = document.getElementById("createRoomCode");
const createPassEl = document.getElementById("createPass");
createRoomCodeEl.value = randomHex(6);
createPassEl.value = randomPassphrase();

document.getElementById("regenRoomBtn").addEventListener("click", () => {
  createRoomCodeEl.value = randomHex(6);
});
document.getElementById("regenPassBtn").addEventListener("click", () => {
  createPassEl.value = randomPassphrase();
});

document.getElementById("createBtn").addEventListener("click", async () => {
  const name = document.getElementById("createName").value.trim() || "anon";
  const code = createRoomCodeEl.value.trim();
  const pass = createPassEl.value.trim();
  if (!pass) return showGateError("Adj meg egy titkosítási jelmondatot.");
  await enterRoom(code, pass, name);
});

document.getElementById("joinBtn").addEventListener("click", async () => {
  const name = document.getElementById("joinName").value.trim() || "anon";
  const code = document.getElementById("joinRoomCode").value.trim();
  const pass = document.getElementById("joinPass").value.trim();
  if (!code || !pass) return showGateError("Add meg a szoba kódot és a jelmondatot.");
  await enterRoom(code, pass, name);
});

function showGateError(msg) {
  gateError.textContent = msg;
  gateError.classList.remove("hidden");
}

async function enterRoom(code, pass, name) {
  roomCode = code;
  displayName = name;
  aesKey = await deriveKey(pass, code);

  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/${encodeURIComponent(code)}`);

  ws.onopen = () => {
    gateView.classList.add("hidden");
    chatView.classList.remove("hidden");
    statusLeft.textContent = `szoba: ${roomCode} · titkosítva (AES-256-GCM)`;
    addSystemLine("Kapcsolódva. Az üzeneteket csak a jelmondatot ismerők tudják elolvasni.");
  };

  ws.onclose = () => {
    addSystemLine("A kapcsolat megszakadt.");
    statusLeft.textContent = "nincs aktív munkamenet";
  };

  ws.onerror = () => showGateError("Nem sikerült csatlakozni a szerverhez.");

  ws.onmessage = async (event) => {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch {
      return;
    }

    if (data.type === "presence") {
      statusLeft.textContent = `szoba: ${roomCode} · ${data.count} kapcsolódott fél · titkosítva`;
      return;
    }
    if (data.type === "error") {
      addSystemLine(`Szerver visszautasította az üzenetet: ${data.reason}`);
      return;
    }
    if (data.type !== "msg") return;

    try {
      const plaintext = await decryptText(aesKey, data.iv, data.ct);
      renderMessage({ name: data.name, text: plaintext, ttl: data.ttl, mine: false });
    } catch {
      renderMessage({ name: data.name, text: "[nem visszafejthető üzenet — hibás jelmondat?]", ttl: 0, mine: false, broken: true });
    }
  };
}

function addSystemLine(text) {
  const div = document.createElement("div");
  div.className = "msg system";
  div.textContent = text;
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function renderMessage({ name, text, ttl, mine, broken }) {
  const wrap = document.createElement("div");
  wrap.className = "msg" + (mine ? " mine" : "");

  const meta = document.createElement("div");
  meta.className = "meta";
  const time = new Date().toTimeString().slice(0, 8);
  meta.innerHTML = `<span>${escapeHtml(name)}</span><span>${time}</span>` +
    (ttl > 0 ? `<span class="ttl-tag">⏳ ${ttl}mp</span>` : "");

  const body = document.createElement("div");
  body.className = "body";
  body.textContent = text;

  wrap.appendChild(meta);
  wrap.appendChild(body);
  messagesEl.appendChild(wrap);
  messagesEl.scrollTop = messagesEl.scrollHeight;

  if (!broken && ttl > 0) {
    const timer = setTimeout(() => {
      wrap.remove();
      destructTimers.delete(timer);
    }, ttl * 1000);
    destructTimers.add(timer);
  }
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

document.getElementById("composerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!ws || ws.readyState !== WebSocket.OPEN) return;

  const input = document.getElementById("msgInput");
  const ttl = parseInt(document.getElementById("ttlSelect").value, 10) || 0;
  const text = input.value;
  if (!text.trim()) return;

  const { iv, ct } = await encryptText(aesKey, text);
  const envelope = { type: "msg", name: displayName, iv, ct, ttl };
  ws.send(JSON.stringify(envelope));
  renderMessage({ name: displayName, text, ttl, mine: true });
  input.value = "";
});

// -------------------------------------------------------------- panic ----

document.getElementById("panicBtn").addEventListener("click", () => {
  destructTimers.forEach(clearTimeout);
  destructTimers.clear();
  aesKey = null;
  roomCode = null;
  displayName = null;
  if (ws) {
    try { ws.close(); } catch {}
    ws = null;
  }
  messagesEl.innerHTML = "";
  sessionStorage.clear();
  chatView.classList.add("hidden");
  gateView.classList.remove("hidden");
  statusLeft.textContent = "nincs aktív munkamenet — munkamenet törölve";
  createRoomCodeEl.value = randomHex(6);
  createPassEl.value = randomPassphrase();
});
