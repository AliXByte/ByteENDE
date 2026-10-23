// ByteENDE · panel JS - talks to /panel/* (session-authenticated) endpoints
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

// Inline SVG icons for markup this script generates at runtime (results that
// come back from /panel/* calls). Kept as real vector icons, matching
// web/templates/_icons.html, instead of OS-rendered symbol/emoji glyphs.
const ICON_COPY = '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>';
const ICON_CHECK = '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12.5 9.5 18 20 6"/></svg>';

async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return r.json();
}
async function postForm(url, formData) {
  const r = await fetch(url, { method: 'POST', body: formData });
  return r.json();
}

// Small visual feedback helper: disables a button and shows a spinner while
// its async action runs, so every tool feels responsive instead of inert.
async function withSpinner(btn, fn) {
  if (!btn) return fn();
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> ' + original;
  try { return await fn(); }
  finally { btn.disabled = false; btn.innerHTML = original; }
}

function markFilled(el, hasValue) {
  if (el) el.classList.toggle('has-value', !!hasValue);
}

/* ---- mobile nav toggle ---- */
const navToggle = $('#navToggle');
if (navToggle) navToggle.onclick = () => document.body.classList.toggle('nav-open');

/* ---- generic segmented-control radio buttons (Network page: mode pickers) ----
   Clicking a [data-radio="group"] button marks it "on" among its .seg siblings
   and writes its data-value into the hidden input #<group>_input, which is
   what actually gets submitted with the form. */
document.addEventListener('click', e => {
  const b = e.target.closest('[data-radio]');
  if (!b) return;
  const seg = b.closest('.seg');
  if (seg) $$('button', seg).forEach(x => x.classList.toggle('on', x === b));
  const input = document.getElementById(b.dataset.radio + '_input');
  if (input) input.value = b.dataset.value;
});

/* ---- show/hide password toggles (login, setup, account) ---- */
const ICON_EYE = '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
const ICON_EYE_OFF = '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18"/><path d="M10.6 5.6A10.6 10.6 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a16.6 16.6 0 0 1-3.2 4M6.5 7.4C4 9.1 2.5 12 2.5 12S6 18.5 12 18.5a9.9 9.9 0 0 0 3.6-.7"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>';
$$('.pw-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.for);
    if (!input) return;
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.innerHTML = show ? ICON_EYE_OFF : ICON_EYE;
    btn.title = show ? 'Hide password' : 'Show password';
  });
});

/* ---- password strength meter (setup page only) ---- */
const setupPw = $('#setupPassword');
if (setupPw) {
  const meter = $('#pwMeter');
  const label = $('#pwMeterLabel');
  setupPw.addEventListener('input', () => {
    const v = setupPw.value;
    let score = 0;
    if (v.length >= 8) score++;
    if (v.length >= 12) score++;
    if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score++;
    if (/\d/.test(v)) score++;
    if (/[^A-Za-z0-9]/.test(v)) score++;
    const tiers = ['', 'weak', 'weak', 'fair', 'good', 'strong'];
    const labels = { '': 'At least 8 characters.', weak: 'Weak — try a longer, less predictable password.', fair: 'Fair.', good: 'Good.', strong: 'Strong.' };
    const tier = v.length === 0 ? '' : tiers[Math.min(score, 5)];
    meter.className = 'pw-meter' + (tier ? ' ' + tier : '');
    label.textContent = v.length === 0 ? 'At least 8 characters.' : labels[tier];
  });
}

/* =================================================================
   Preferences (Customize page) — everything here is client-side only
   (localStorage), applied live via CSS variables / data-attributes.
   ================================================================= */
const PREFS_KEY = 'byteende:prefs';
const DEFAULT_PREFS = {
  accent: 'cyan', density: 'comfortable', bgEffects: true, animations: true,
  confirmDelete: true, copyToast: true, outputFont: 'mono', defaultCodec: 'base64',
};

function loadPrefs() {
  try { return Object.assign({}, DEFAULT_PREFS, JSON.parse(localStorage.getItem(PREFS_KEY) || '{}')); }
  catch (e) { return Object.assign({}, DEFAULT_PREFS); }
}
function savePrefs(p) {
  try { localStorage.setItem(PREFS_KEY, JSON.stringify(p)); } catch (e) {}
}
function applyPrefs(p) {
  const html = document.documentElement;
  html.setAttribute('data-accent', p.accent);
  html.setAttribute('data-density', p.density);
  html.setAttribute('data-fx', p.bgEffects ? 'on' : 'off');
  html.setAttribute('data-anim', p.animations ? 'on' : 'off');
  $$('.out-box').forEach(el => el.classList.toggle('font-sans', p.outputFont === 'sans'));
}

let PREFS = loadPrefs();
applyPrefs(PREFS);

function toast(msg, iconSvg) {
  if (!PREFS.copyToast) return;
  const stack = $('#toastStack'); if (!stack) return;
  const el = document.createElement('div');
  el.className = 'toast';
  el.innerHTML = (iconSvg || '') + '<span></span>';
  el.querySelector('span').textContent = msg;
  stack.appendChild(el);
  setTimeout(() => el.remove(), 2400);
}

// Confirmation for any form carrying data-confirm (keeps us CSP-clean: no inline onsubmit=)
document.addEventListener('submit', e => {
  const form = e.target.closest('form[data-confirm]');
  if (!form) return;
  if (!PREFS.confirmDelete) return; // user turned confirmations off in Customize
  if (!window.confirm(form.dataset.confirm)) e.preventDefault();
});

/* ---- Customize page wiring (only present on /settings) ---- */
const accentSwatches = $('#accentSwatches');
if (accentSwatches) {
  const syncUI = () => {
    $$('#accentSwatches .swatch').forEach(b => b.classList.toggle('on', b.dataset.accent === PREFS.accent));
    $$('#densitySeg button').forEach(b => b.classList.toggle('on', b.dataset.density === PREFS.density));
    $('#defaultCodecSel').value = PREFS.defaultCodec;
    $('#outputFontSel').value = PREFS.outputFont;
    $('#bgFxToggle').checked = PREFS.bgEffects;
    $('#animToggle').checked = PREFS.animations;
    $('#confirmDeleteToggle').checked = PREFS.confirmDelete;
    $('#copyToastToggle').checked = PREFS.copyToast;
  };
  const commit = () => { savePrefs(PREFS); applyPrefs(PREFS); };

  accentSwatches.addEventListener('click', e => {
    const b = e.target.closest('[data-accent]'); if (!b) return;
    PREFS.accent = b.dataset.accent; commit(); syncUI();
  });
  $('#densitySeg').addEventListener('click', e => {
    const b = e.target.closest('[data-density]'); if (!b) return;
    PREFS.density = b.dataset.density; commit(); syncUI();
  });
  $('#defaultCodecSel').onchange = e => { PREFS.defaultCodec = e.target.value; commit(); };
  $('#outputFontSel').onchange = e => { PREFS.outputFont = e.target.value; commit(); };
  $('#bgFxToggle').onchange = e => { PREFS.bgEffects = e.target.checked; commit(); };
  $('#animToggle').onchange = e => { PREFS.animations = e.target.checked; commit(); };
  $('#confirmDeleteToggle').onchange = e => { PREFS.confirmDelete = e.target.checked; commit(); };
  $('#copyToastToggle').onchange = e => { PREFS.copyToast = e.target.checked; commit(); };

  $('#exportPrefsBtn').onclick = () => {
    const blob = new Blob([JSON.stringify(PREFS, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'byteende-settings.json';
    a.click();
    URL.revokeObjectURL(a.href);
  };
  $('#importPrefsBtn').onclick = () => $('#importPrefsFile').click();
  $('#importPrefsFile').addEventListener('change', async () => {
    const f = $('#importPrefsFile').files[0]; if (!f) return;
    try {
      const data = JSON.parse(await f.text());
      PREFS = Object.assign({}, DEFAULT_PREFS, data);
      commit(); syncUI();
    } catch (e) { alert('That file is not valid ByteENDE settings JSON.'); }
  });
  $('#resetPrefsBtn').onclick = () => {
    PREFS = Object.assign({}, DEFAULT_PREFS); commit(); syncUI();
  };

  syncUI();
}

document.addEventListener('click', e => {
  const c = e.target.closest('[data-copy-target]');
  if (c) {
    const el = document.getElementById(c.dataset.copyTarget);
    const text = el.textContent.trim();
    navigator.clipboard.writeText(text).catch(() => {});
    const original = c.innerHTML;
    c.innerHTML = ICON_CHECK;
    setTimeout(() => c.innerHTML = original, 1000);
    toast('Copied to clipboard', ICON_CHECK);
  }
});

/* ---- codec ---- */
let curCodec = 'base64';
const codecTabs = $('#codecTabs');
if (codecTabs) {
  // Apply the Customize-page default on first load.
  if (typeof PREFS !== 'undefined' && PREFS.defaultCodec && PREFS.defaultCodec !== 'base64') {
    curCodec = PREFS.defaultCodec;
    $$('#codecTabs button').forEach(x => x.classList.toggle('on', x.dataset.c === curCodec));
  }
  codecTabs.addEventListener('click', e => {
    const b = e.target.closest('[data-c]'); if (!b) return;
    curCodec = b.dataset.c;
    $$('#codecTabs button').forEach(x => x.classList.toggle('on', x === b));
  });
  const run = async (mode, btn) => withSpinner(btn, async () => {
    $('#codecErr').textContent = '';
    $('#codecModeLbl').textContent = mode;
    const r = await post('/panel/codec', { codec: curCodec, mode, text: $('#codecIn').value });
    if (r.ok) { $('#codecOut').innerHTML = esc(r.result) + '<button class="copy" data-copy-target="codecOut" title="Copy">' + ICON_COPY + '</button>'; markFilled($('#codecOut'), true); }
    else { $('#codecErr').textContent = r.error; markFilled($('#codecOut'), false); }
  });
  $('#codecEncode').onclick = () => run('encode', $('#codecEncode'));
  $('#codecDecode').onclick = () => run('decode', $('#codecDecode'));
}

/* ---- hash ---- */
if ($('#hashRun')) {
  $('#hashRun').onclick = () => withSpinner($('#hashRun'), async () => {
    const r = await post('/panel/hash', { text: $('#hashIn').value });
    if (r.ok) {
      $('#hashOut').innerHTML = Object.entries(r.result).map(([k, v]) =>
        `<div class="field"><label>${k.toUpperCase()}</label><div class="out-box has-value" id="h_${k}">${v}<button class="copy" data-copy-target="h_${k}" title="Copy">${ICON_COPY}</button></div></div>`).join('');
    }
  });
}

/* ---- JWT ---- */
if ($('#jwtTabs')) {
  $('#jwtTabs').addEventListener('click', e => {
    const b = e.target.closest('[data-j]'); if (!b) return;
    $$('#jwtTabs button').forEach(x => x.classList.toggle('on', x === b));
    $('#jwtDecodeBox').style.display = b.dataset.j === 'decode' ? '' : 'none';
    $('#jwtEncodeBox').style.display = b.dataset.j === 'encode' ? '' : 'none';
  });
  $('#jwtDecodeRun').onclick = () => withSpinner($('#jwtDecodeRun'), async () => {
    const r = await post('/panel/jwt/decode', { token: $('#jwtToken').value });
    $('#jwtOut').textContent = r.ok ? JSON.stringify(r.result, null, 2) : 'Error: ' + r.error;
    markFilled($('#jwtOut'), r.ok);
  });
  $('#jwtEncodeRun').onclick = () => withSpinner($('#jwtEncodeRun'), async () => {
    const r = await post('/panel/jwt/encode', { payload: $('#jwtPayload').value, secret: $('#jwtSecret').value, alg: $('#jwtAlg').value });
    $('#jwtEncOut').innerHTML = r.ok ? esc(r.result) + '<button class="copy" data-copy-target="jwtEncOut" title="Copy">' + ICON_COPY + '</button>' : 'Error: ' + r.error;
    markFilled($('#jwtEncOut'), r.ok);
  });
}

/* ---- AES ---- */
let aesMode = 'encrypt';
if ($('#aesTabs')) {
  $('#aesTabs').addEventListener('click', e => {
    const b = e.target.closest('[data-a]'); if (!b) return;
    aesMode = b.dataset.a;
    $$('#aesTabs button').forEach(x => x.classList.toggle('on', x === b));
    $('#aesInLbl').textContent = aesMode === 'encrypt' ? 'Text' : 'Encrypted blob (Base64)';
  });
  $('#aesRun').onclick = () => withSpinner($('#aesRun'), async () => {
    const url = aesMode === 'encrypt' ? '/panel/aes/encrypt' : '/panel/aes/decrypt';
    const key = aesMode === 'encrypt' ? 'text' : 'blob';
    const r = await post(url, { [key]: $('#aesIn').value, password: $('#aesPass').value });
    $('#aesOut').innerHTML = r.ok ? esc(r.result) + '<button class="copy" data-copy-target="aesOut" title="Copy">' + ICON_COPY + '</button>' : 'Error: ' + r.error;
    markFilled($('#aesOut'), r.ok);
  });
}

/* ---- QR ---- */
if ($('#qrTabs')) {
  $('#qrTabs').addEventListener('click', e => {
    const b = e.target.closest('[data-q]'); if (!b) return;
    $$('#qrTabs button').forEach(x => x.classList.toggle('on', x === b));
    $('#qrGenBox').style.display = b.dataset.q === 'gen' ? '' : 'none';
    $('#qrReadBox').style.display = b.dataset.q === 'read' ? '' : 'none';
  });
  $('#qrGenRun').onclick = () => withSpinner($('#qrGenRun'), async () => {
    const r = await post('/panel/qr/generate', { text: $('#qrText').value });
    $('#qrImgOut').innerHTML = r.ok ? `<img src="${r.result}" style="max-width:220px;border-radius:10px;border:1px solid var(--border);box-shadow:0 10px 30px rgba(34,211,238,.18)">` : '<div class="err">' + r.error + '</div>';
  });
  $('#qrDrop').onclick = () => $('#qrFile').click();
  ['dragover', 'dragleave', 'drop'].forEach(evt => {
    $('#qrDrop').addEventListener(evt, e => {
      e.preventDefault();
      $('#qrDrop').classList.toggle('drag', evt === 'dragover');
      if (evt === 'drop' && e.dataTransfer.files[0]) { $('#qrFile').files = e.dataTransfer.files; $('#qrFile').dispatchEvent(new Event('change')); }
    });
  });
  $('#qrFile').addEventListener('change', async () => {
    const f = $('#qrFile').files[0]; if (!f) return;
    const fd = new FormData(); fd.append('image', f);
    const r = await postForm('/panel/qr/read', fd);
    $('#qrReadOut').textContent = r.ok ? r.result.join('\n') : 'Error: ' + r.error;
    markFilled($('#qrReadOut'), r.ok);
  });
}

function esc(s) { return String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])); }
