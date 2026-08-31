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
  assessment: ["assessment-signature", "assessment-trust", "assessment-jtag"],
  binarylab: ["binarylab-unsigned", "binarylab-openssl", "binarylab-pki"],
  bootchain: ["bootchain-rom", "bootchain-bootloader", "bootchain-kernel"]
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

// -- Binary Lab: real envelope schema from signing/sign_artifact.py, rendered as a byte/field layout. --
const LAYOUT_DATA = {
  unsigned: {
    label: "On disk", title: "Unsigned artifact", filecount: "1 file",
    caption: "No sidecar file exists. There is nothing to verify: any party that can write to this path can silently replace candump.",
    blocks: [{ kind: "artifact", label: "candump", sub: "ELF64 executable \u2014 raw build output" }]
  },
  openssl: {
    label: "On disk", title: "OpenSSL-signed artifact", filecount: "2 files",
    caption: "candump is byte-identical to the unsigned build. Trust is carried entirely by the adjacent candump.sig envelope, verified against an explicitly provisioned public key.",
    blocks: [
      { kind: "artifact", label: "candump", sub: "ELF64 executable \u2014 byte-identical to unsigned build" },
      { kind: "envelope", label: "candump.sig", sub: "JSON signature envelope (secure-signing-envelope/v1)", fields: [
        ["format", "secure-signing-envelope/v1"], ["method", "openssl"], ["digest_algorithm", "sha256"],
        ["artifact_sha256", "64-char hex digest"], ["signature_base64", "base64 EC signature"]
      ] }
    ]
  },
  pki: {
    label: "On disk", title: "PKI-signed artifact", filecount: "2 files",
    caption: "Same byte-identical candump. The envelope grows by two fields so a verifier only needs the pinned Root CA \u2014 not a per-device public key \u2014 to validate trust.",
    blocks: [
      { kind: "artifact", label: "candump", sub: "ELF64 executable \u2014 byte-identical to unsigned build" },
      { kind: "envelope", label: "candump.sig", sub: "JSON signature envelope (secure-signing-envelope/v1)", fields: [
        ["format", "secure-signing-envelope/v1"], ["method", "pki"], ["digest_algorithm", "sha256"],
        ["artifact_sha256", "64-char hex digest"],
        ["certificate_pem", "leaf certificate (added)", true], ["chain_pem", "intermediate CA chain (added)", true],
        ["signature_base64", "base64 EC signature"]
      ] }
    ]
  }
};

function renderLayout(key) {
  const data = LAYOUT_DATA[key];
  document.querySelector('#layout-label').textContent = data.label;
  document.querySelector('#layout-title').textContent = data.title;
  document.querySelector('#layout-filecount').textContent = data.filecount;
  document.querySelector('#layout-caption').textContent = data.caption;
  document.querySelector('#layout-diagram').innerHTML = data.blocks.map((block) => {
    if (block.kind === 'artifact') {
      return `<div class="layout-block layout-artifact"><strong>${block.label}</strong><span>${block.sub}</span></div>`;
    }
    const fields = block.fields.map(([name, value, added]) => `<div class="layout-field${added ? ' added' : ''}"><code>${name}</code><span>${value}</span></div>`).join('');
    return `<div class="layout-block layout-envelope"><strong>${block.label}</strong><span>${block.sub}</span><div class="layout-fields">${fields}</div></div>`;
  }).join('<div class="layout-plus">+</div>');
}

document.querySelectorAll('[data-layout]').forEach((button) => button.addEventListener('click', () => {
  document.querySelectorAll('[data-layout]').forEach((item) => item.classList.toggle('active', item === button));
  renderLayout(button.dataset.layout);
  completeObjective(`binarylab-${button.dataset.layout}`, `Binary Lab: inspected the ${button.dataset.layout} on-disk layout.`);
}));

// -- Boot Chain: reference model inspired by TI TDA4x-class (Jacinto 7) secure boot. --
const BOOT_STAGES = [
  { id: 'rom', group: 'rom', name: 'Boot ROM', tag: 'Immutable', role: 'First code executed on power-up. Reads the boot device and an X.509-wrapped boot image before running anything else.', verifiedBy: 'Fixed silicon logic \u2014 cannot be patched or bypassed', key: 'SoC vendor root public-key hash burned into eFuse/OTP' },
  { id: 'r5spl', group: 'rom', name: 'R5 SPL', tag: 'Secondary loader', role: 'Runs on the safety island (e.g. Cortex-R5F). Minimal DDR and clock bring-up, then hands off to the secure core.', verifiedBy: 'Boot ROM, using the same root-of-trust certificate chain', key: 'Same root public key / certificate chain as the ROM stage' },
  { id: 'securecore', group: 'rom', name: 'Secure core (HSM role)', tag: 'TIFS / DMSC-class', role: 'Dedicated security microcontroller. Owns root keys and provides signature verification and crypto services to every other core over a secure message queue.', verifiedBy: 'Boot ROM', key: 'Hardware root key in on-chip secure storage \u2014 never exposed to application cores' },
  { id: 'a72spl', group: 'bootloader', name: 'A72 SPL', tag: 'Bootloader stage', role: 'Brings up DDR for the main application cores (e.g. Cortex-A72) and loads the next stage.', verifiedBy: 'Secure core / HSM', key: 'Leaf signing key from the same PKI chain used for application artifacts' },
  { id: 'uboot', group: 'bootloader', name: 'U-Boot', tag: 'Bootloader', role: 'Loads the kernel, device tree, and initramfs as a signed FIT image.', verifiedBy: "Public key compiled into U-Boot's control device tree (CONFIG_FIT_SIGNATURE)", key: "Root CA / signing public key \u2014 matches this repo's meta-uboot-secure layer" },
  { id: 'kernel', group: 'kernel', name: 'Linux kernel', tag: 'OS', role: 'Verifies signed kernel modules before loading them.', verifiedBy: 'Kernel keyring populated at build time (CONFIG_MODULE_SIG)', key: "Module signing key \u2014 demonstrated with the WireGuard module in this repo" },
  { id: 'jtag', group: 'kernel', name: 'JTAG debug gate', tag: 'Parallel path', role: 'Not part of the linear boot chain. Disabled by default; a debug host must sign a fresh device nonce to unlock one session.', verifiedBy: 'Secure core / boot ROM trust anchor', key: 'Same signing key material \u2014 see the JTAG Range mission' }
];

function renderBootStepper() {
  document.querySelector('#boot-stepper').innerHTML = BOOT_STAGES.map((stage, index) => `<button class="stage-btn${index === 0 ? ' active' : ''}" data-stage="${stage.id}"><span>${index + 1}</span>${stage.name}</button>`).join('<div class="stage-link"></div>');
  document.querySelectorAll('.stage-btn').forEach((button) => button.addEventListener('click', () => {
    document.querySelectorAll('.stage-btn').forEach((item) => item.classList.toggle('active', item === button));
    renderStageDetail(button.dataset.stage);
  }));
  renderStageDetail(BOOT_STAGES[0].id);
}

function renderStageDetail(id) {
  const stage = BOOT_STAGES.find((item) => item.id === id);
  document.querySelector('#stage-detail').innerHTML = `<div class="panel-header"><div><p class="eyebrow">${stage.tag}</p><h2>${stage.name}</h2></div></div><p class="caption">${stage.role}</p><dl><div><dt>Verified by</dt><dd>${stage.verifiedBy}</dd></div><div><dt>Key material</dt><dd>${stage.key}</dd></div></dl>`;
  completeObjective(`bootchain-${stage.group}`, `Boot Chain: traced the ${stage.name} stage.`);
}

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
renderLayout('unsigned');
renderBootStepper();
drawTrustCanvas();
renderProgress();
tickClock();
setInterval(tickClock, 1000);
runBootSequence();
