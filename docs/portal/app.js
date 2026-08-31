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

function changeView(view) {
  document.querySelectorAll('.view').forEach((element) => element.classList.toggle('active', element.id === view));
  document.querySelectorAll('[data-view]').forEach((element) => element.classList.toggle('active', element.dataset.view === view));
  window.location.hash = view;
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
}));

let priorResponse = false;
document.querySelector('#issue-nonce').addEventListener('click', () => {
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(12)), (value) => value.toString(16).padStart(2, '0')).join('');
  document.querySelector('#nonce-value').textContent = nonce;
  document.querySelector('#protocol-event').textContent = 'Target issued a fresh 32-byte nonce';
  document.querySelector('#protocol-line').className = 'protocol-line';
  document.querySelector('#jtag-state').textContent = 'Challenge pending';
  document.querySelector('#submit-response').disabled = false;
  document.querySelector('#replay-response').disabled = !priorResponse;
});
document.querySelector('#submit-response').addEventListener('click', () => {
  priorResponse = true;
  document.querySelector('#protocol-event').textContent = 'Trusted response verified; session unlocked';
  document.querySelector('#protocol-line').className = 'protocol-line verified';
  document.querySelector('#jtag-state').textContent = 'Unlocked once';
  document.querySelector('#submit-response').disabled = true;
  document.querySelector('#replay-response').disabled = false;
});
document.querySelector('#replay-response').addEventListener('click', () => {
  document.querySelector('#protocol-event').textContent = 'Replay rejected; nonce was already consumed';
  document.querySelector('#protocol-line').className = 'protocol-line rejected';
  document.querySelector('#jtag-state').textContent = 'Locked';
});

function renderAssessments(filter = 'all') {
  document.querySelector('#test-grid').innerHTML = assessments.map(([category, title, detail, outcome]) => `<article class="panel test-card ${filter !== 'all' && filter !== category ? 'hidden' : ''}"><span class="result">PASS: ${outcome}</span><h2>${title}</h2><p>${detail}</p><code>${category.toUpperCase()} BOUNDARY</code></article>`).join('');
}
document.querySelectorAll('.filter').forEach((button) => button.addEventListener('click', () => {
  document.querySelectorAll('.filter').forEach((item) => item.classList.toggle('active', item === button));
  renderAssessments(button.dataset.filter);
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
  connect(0,1,'#dfa13c'); connect(1,2,'#087b78'); connect(2,3,'#087b78'); connect(2,4,'#b84c42');
  nodes.forEach(([x,y,title,detail], index) => { const [px,py]=point([x,y]); context.fillStyle='#fbfcf8'; context.strokeStyle=index===4?'#b84c42':index===1?'#dfa13c':'#087b78'; context.lineWidth=2; context.fillRect(px-61,py-25,122,50); context.strokeRect(px-61,py-25,122,50); context.fillStyle='#102527'; context.fillText(title,px,py-4); context.fillStyle='#597073'; context.font='10px DM Mono'; context.fillText(detail,px,py+12); context.font='600 12px Manrope'; });
}
window.addEventListener('resize', drawTrustCanvas);
renderAssessments();
document.querySelector('#envelope-code').textContent = signingMethods.openssl.envelope;
drawTrustCanvas();
changeView(window.location.hash.slice(1) || 'overview');