const signingMethods = {
  openssl: {
    label: "Development signing", title: "Direct key-pair trust",
    copy: "A P-256 private key signs the SHA-256 digest. The verifier receives a separately provisioned public key and accepts only a matching signature.",
    facts: [["Signer material", "Private EC P-256 key"], ["Verifier anchor", "Explicit public key"], ["Use case", "Local builds and CI smoke tests"]],
    envelope: '{\n  "format": "secure-signing-envelope/v1",\n  "method": "openssl",\n  "digest_algorithm": "sha256",\n  "artifact_sha256": "...",\n  "signature_base64": "..."\n}'
  },
  pki: {
    label: "Release signing", title: "Rotatable PKI trust",
    copy: "The leaf signing key is certified by an Intermediate CA. The target pins only the Root CA, enabling controlled leaf-key rotation without changing deployed trust anchors.",
    facts: [["Signer material", "Leaf EC P-256 key + certificate"], ["Verifier anchor", "Pinned Root CA certificate"], ["Use case", "Release images and production debug access"]],
    envelope: '{\n  "format": "secure-signing-envelope/v1",\n  "method": "pki",\n  "artifact_sha256": "...",\n  "certificate_pem": "Leaf certificate",\n  "chain_pem": "Intermediate CA",\n  "signature_base64": "..."\n}'
  }
};

const assessments = [
  ["signature", "Artifact tampering", "The recorded SHA-256 digest no longer matches modified artifact bytes.", "Digest check rejects"],
  ["signature", "Malformed envelope", "Invalid JSON, missing fields, unsupported format, and malformed Base64 are tested.", "Parser rejects"],
  ["signature", "Method downgrade", "An envelope claiming an unsupported signing method is not accepted as valid.", "Policy rejects"],
  ["trust", "Key substitution", "A valid signature created by a replacement private key is verified against the pinned key.", "Signature rejects"],
  ["trust", "Untrusted Root CA", "A leaf certificate that chains to a different Root CA is tested against the pinned root.", "Chain validation rejects"],
  ["trust", "Leaf key mismatch", "The signer checks that the provided private key matches the PKI leaf certificate.", "Signing rejects"],
  ["jtag", "Nonce replay", "A previously accepted signed challenge is presented after the target has consumed it.", "Session stays locked"],
  ["jtag", "Wrong challenge", "A response that signs different nonce bytes is presented to the target.", "Session stays locked"]
];

// -- Mission progress: client-side only, no data ever leaves this page. --
const OBJECTIVE_POINTS = 10;
const OBJECTIVE_GROUPS = {
  overview: ["overview-briefed"],
  signing: ["signing-openssl", "signing-pki"],
  jtag: ["jtag-issue", "jtag-unlock", "jtag-replay"],
  assessment: ["assessment-signature", "assessment-trust", "assessment-jtag"]
};
const TOTAL_OBJECTIVES = Object.values(OBJECTIVE_GROUPS).flat().length;
const PROGRESS_KEY = "ecu-security-range-progress";
let progress = { objectives: {} };
try {
  progress = { objectives: {}, ...JSON.parse(localStorage.getItem(PROGRESS_KEY) || "{}") };
} catch (error) {
  progress = { objectives: {} };
}

function saveProgress() {
  localStorage.setItem(PROGRESS_KEY, JSON.stringify(progress));
}

function logEvent(message, tone = "info") {
  const log = document.querySelector('#console-log');
  const line = document.createElement('div');
  line.className = `log-line ${tone}`;
  const time = new Date().toLocaleTimeString('en-GB', { hour12: false });
  line.innerHTML = `<span class="time">[${time}]</span>${message}`;
  log.appendChild(line);
  while (log.children.length > 60) log.removeChild(log.firstChild);
  log.scrollTop = log.scrollHeight;
}

function renderProgress() {
  const completed = Object.values(progress.objectives).filter(Boolean).length;
  document.querySelector('#trust-score').innerHTML = `${completed * OBJECTIVE_POINTS}<small>/${TOTAL_OBJECTIVES * OBJECTIVE_POINTS} XP</small>`;
  document.querySelectorAll('[data-objective]').forEach((item) => item.classList.toggle('done', Boolean(progress.objectives[item.dataset.objective])));
  Object.entries(OBJECTIVE_GROUPS).forEach(([group, objectives]) => {
    const done = objectives.every((objective) => progress.objectives[objective]);
    const indicator = document.querySelector(`#check-${group}`);
    if (indicator) indicator.classList.toggle('done', done);
  });
}

function completeObjective(id, message) {
  if (progress.objectives[id]) return;
  progress.objectives[id] = true;
  saveProgress();
  renderProgress();
  if (message) logEvent(message, 'success');
}

function changeView(view) {
  document.querySelectorAll('.view').forEach((element) => element.classList.toggle('active', element.id === view));
  document.querySelectorAll('.mission').forEach((element) => element.classList.toggle('active', element.dataset.view === view));
  window.location.hash = view;
  if (view === 'overview') completeObjective('overview-briefed', 'Briefing reviewed: trust path from build to JTAG gate.');
}

document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => changeView(button.dataset.view)));

document.querySelectorAll('.method').forEach((button) => button.addEventListener('click', () => {
  document.querySelectorAll('.method').forEach((item) => item.classList.toggle('active', item === button));
  const method = signingMethods[button.dataset.method];
  document.querySelector('#method-label').textContent = method.label;
  document.querySelector('#method-title').textContent = method.title;
  document.querySelector('#method-copy').textContent = method.copy;
  document.querySelector('#method-facts').innerHTML = method.facts.map(([term, value]) => `<div><dt>${term}</dt><dd>${value}</dd></div>`).join('');
  document.querySelector('#envelope-code').textContent = method.envelope;
  completeObjective(`signing-${button.dataset.method}`, `Signing Bay: inspected ${method.title.toLowerCase()}.`);
}));

function setGateStatus(state, label) {
  const pill = document.querySelector('#gate-status');
  pill.className = `pill ${state}`;
  pill.textContent = label;
  document.querySelector('#jtag-state').textContent = label;
}

let priorResponse = false;
document.querySelector('#issue-nonce').addEventListener('click', () => {
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(12)), (value) => value.toString(16).padStart(2, '0')).join('');
  document.querySelector('#nonce-value').textContent = nonce;
  document.querySelector('#protocol-event').textContent = 'Target issued a fresh 32-byte nonce';
  document.querySelector('#protocol-line').className = 'protocol-line';
  setGateStatus('pending', 'Pending');
  document.querySelector('#submit-response').disabled = false;
  document.querySelector('#replay-response').disabled = !priorResponse;
  completeObjective('jtag-issue', `JTAG Range: target issued nonce ${nonce.slice(0, 8)}...`);
  logEvent('Nonce issued. Debug port remains locked until a trusted response arrives.');
});
document.querySelector('#submit-response').addEventListener('click', () => {
  priorResponse = true;
  document.querySelector('#protocol-event').textContent = 'Trusted response verified; session unlocked';
  document.querySelector('#protocol-line').className = 'protocol-line verified';
  setGateStatus('unlocked', 'Unlocked');
  document.querySelector('#submit-response').disabled = true;
  document.querySelector('#replay-response').disabled = false;
  completeObjective('jtag-unlock', 'JTAG Range: signed response verified. Debug session unlocked (one time).');
});
document.querySelector('#replay-response').addEventListener('click', () => {
  document.querySelector('#protocol-event').textContent = 'Replay rejected; nonce was already consumed';
  document.querySelector('#protocol-line').className = 'protocol-line rejected';
  setGateStatus('locked', 'Locked');
  completeObjective('jtag-replay', 'JTAG Range: replayed response rejected. Gate re-locked.');
  logEvent('Replay attempt rejected: nonce already consumed by a prior session.', 'danger');
});

function renderAssessments(filter = 'all') {
  document.querySelector('#test-grid').innerHTML = assessments.map(([category, title, detail, outcome]) => `<article class="panel test-card ${filter !== 'all' && filter !== category ? 'hidden' : ''}"><span class="result">PASS: ${outcome}</span><h2>${title}</h2><p>${detail}</p><code>${category.toUpperCase()} BOUNDARY</code></article>`).join('');
}
document.querySelectorAll('.filter').forEach((button) => button.addEventListener('click', () => {
  document.querySelectorAll('.filter').forEach((item) => item.classList.toggle('active', item === button));
  renderAssessments(button.dataset.filter);
  if (button.dataset.filter !== 'all') {
    completeObjective(`assessment-${button.dataset.filter}`, `Red Team Ops: reviewed ${button.dataset.filter} attack cases.`);
  }
}));

function drawTrustCanvas() {
  const canvas = document.querySelector('#trust-canvas');
  const context = canvas.getContext('2d');
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth;
  const height = canvas.clientWidth * 0.43;
  canvas.width = width * ratio; canvas.height = height * ratio; context.scale(ratio, ratio);
  context.clearRect(0, 0, width, height); context.font = '600 12px Manrope'; context.textAlign = 'center';
  const nodes = [[.12,.3,'Build','can-utils / U-Boot'],[.39,.3,'Signer','Key or PKI leaf'],[.66,.3,'Verifier','Pinned trust'],[.88,.3,'Yocto target','Public Root CA'],[.66,.74,'JTAG gate','Fresh nonce']];
  const point = ([x,y]) => [width*x,height*y];
  const connect = (first, second, color) => { const [x1,y1]=point(nodes[first]); const [x2,y2]=point(nodes[second]); context.strokeStyle=color; context.lineWidth=2; context.beginPath(); context.moveTo(x1,y1); context.lineTo(x2,y2); context.stroke(); };
  connect(0,1,'#ffb648'); connect(1,2,'#43d9ff'); connect(2,3,'#43d9ff'); connect(2,4,'#ff5d5d');
  nodes.forEach(([x,y,title,detail], index) => { const [px,py]=point([x,y]); context.fillStyle='rgba(10,17,22,.9)'; context.strokeStyle=index===4?'#ff5d5d':index===1?'#ffb648':'#43d9ff'; context.lineWidth=2; context.fillRect(px-61,py-25,122,50); context.strokeRect(px-61,py-25,122,50); context.fillStyle='#d7ecf5'; context.fillText(title,px,py-4); context.fillStyle='#7d97a3'; context.font='10px DM Mono'; context.fillText(detail,px,py+12); context.font='600 12px Manrope'; });
}
window.addEventListener('resize', drawTrustCanvas);

document.querySelector('#console-toggle').addEventListener('click', () => {
  const dock = document.querySelector('.console-dock');
  const collapsed = dock.classList.toggle('collapsed');
  document.querySelector('#console-toggle').setAttribute('aria-expanded', String(!collapsed));
});

function tickClock() {
  document.querySelector('#sim-clock').textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
}

const BOOT_LINES = [
  'Mounting secure signing pipeline...',
  'Loading pinned trust anchors (OpenSSL + PKI)...',
  'Arming JTAG debug-authentication range...',
  'Range online. Standing by for operator.'
];

function runBootSequence() {
  const overlay = document.querySelector('#boot-overlay');
  const log = document.querySelector('#boot-log');
  const fill = document.querySelector('#boot-fill');
  const enterButton = document.querySelector('#enter-range');
  requestAnimationFrame(() => { fill.style.width = '100%'; });
  BOOT_LINES.forEach((text, index) => {
    setTimeout(() => { log.textContent += `> ${text}\n`; }, 500 + index * 480);
  });
  setTimeout(() => { enterButton.disabled = false; }, 500 + BOOT_LINES.length * 480);
  const enter = () => {
    overlay.classList.add('hidden');
    logEvent('Operator entered the range. Mission timer started.', 'success');
    changeView(window.location.hash.slice(1) || 'overview');
  };
  enterButton.addEventListener('click', enter);
}

renderAssessments();
document.querySelector('#envelope-code').textContent = signingMethods.openssl.envelope;
drawTrustCanvas();
renderProgress();
tickClock();
setInterval(tickClock, 1000);
runBootSequence();
