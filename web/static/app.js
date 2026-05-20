'use strict';

// ── State ────────────────────────────────────────────────────────────────────

const state = {
  config: {},
  pkce: { verifier: '', challenge: '', method: 'S256' },
};

// ── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  loadConfig();

  const params = new URLSearchParams(window.location.search);
  const flowId = params.get('flow');
  if (flowId) {
    window.history.replaceState({}, '', '/');
    switchTab('history');
    loadHistory(flowId);
  }
});

function initTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + tab).classList.add('active');
      if (tab === 'flow') renderFlowPreview();
      if (tab === 'history') loadHistory();
    });
  });
}

// ── Config ───────────────────────────────────────────────────────────────────

async function loadConfig() {
  try {
    const res = await fetch('/api/config');
    const cfg = await res.json();
    state.config = cfg;
    applyConfigToForm(cfg);
    prefillFromConfig();
    renderFlowPreview();
  } catch (e) {
    showStatus('config-status', 'Failed to load config: ' + e.message, true);
  }
}

function applyConfigToForm(cfg) {
  setVal('cfg-issuer-url', cfg.issuer_url);
  setVal('cfg-auth-url', cfg.authorization_url);
  setVal('cfg-token-url', cfg.token_url);
  setVal('cfg-userinfo-url', cfg.userinfo_url);
  setVal('cfg-introspection-url', cfg.introspection_url);
  setVal('cfg-end-session-url', cfg.end_session_url);
  setVal('cfg-jwks-uri', cfg.jwks_uri);
  setVal('cfg-client-id', cfg.client_id);
  setVal('cfg-client-secret', cfg.client_secret);
  setVal('cfg-redirect-uri', cfg.redirect_uri);
  setVal('cfg-scopes', (cfg.scopes || []).join(' '));
  setSelectVal('cfg-response-type', cfg.response_type || 'code');
  setSelectVal('cfg-response-mode', cfg.response_mode || '');
  document.getElementById('cfg-pkce-enabled').checked = !!cfg.pkce_enabled;
  setSelectVal('cfg-pkce-method', cfg.pkce_method || 'S256');
  setVal('cfg-extra-authorize', cfg.extra_authorize_params
    ? JSON.stringify(cfg.extra_authorize_params, null, 2) : '{}');
  setVal('cfg-extra-token', cfg.extra_token_params
    ? JSON.stringify(cfg.extra_token_params, null, 2) : '{}');
}

function readConfigFromForm() {
  const extraAuthorize = parseJSON(getVal('cfg-extra-authorize'), {});
  const extraToken = parseJSON(getVal('cfg-extra-token'), {});
  const scopes = getVal('cfg-scopes').split(/\s+/).filter(Boolean);

  return {
    issuer_url: getVal('cfg-issuer-url'),
    authorization_url: getVal('cfg-auth-url'),
    token_url: getVal('cfg-token-url'),
    userinfo_url: getVal('cfg-userinfo-url'),
    introspection_url: getVal('cfg-introspection-url'),
    end_session_url: getVal('cfg-end-session-url'),
    jwks_uri: getVal('cfg-jwks-uri'),
    client_id: getVal('cfg-client-id'),
    client_secret: getVal('cfg-client-secret'),
    redirect_uri: getVal('cfg-redirect-uri'),
    scopes,
    response_type: getVal('cfg-response-type'),
    response_mode: getVal('cfg-response-mode'),
    pkce_enabled: document.getElementById('cfg-pkce-enabled').checked,
    pkce_method: getVal('cfg-pkce-method'),
    extra_authorize_params: extraAuthorize,
    extra_token_params: extraToken,
  };
}

async function saveConfig() {
  const cfg = readConfigFromForm();
  try {
    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    });
    const saved = await res.json();
    state.config = saved;
    prefillFromConfig();
    showStatus('config-status', 'Saved ✓');
    setTimeout(() => showStatus('config-status', ''), 2000);
  } catch (e) {
    showStatus('config-status', 'Error: ' + e.message, true);
  }
}

function prefillFromConfig() {
  const c = state.config;
  setVal('disc-issuer-url', c.issuer_url || '');
  setVal('auth-url', c.authorization_url || '');
  setVal('auth-client-id', c.client_id || '');
  setVal('auth-redirect-uri', c.redirect_uri || '');
  setVal('auth-scopes', (c.scopes || []).join(' '));
  setVal('auth-response-type', c.response_type || 'code');
  setVal('auth-response-mode', c.response_mode || '');
  setSelectVal('auth-pkce-method', c.pkce_method || 'S256');
  setVal('tok-token-url', c.token_url || '');
  setVal('tok-client-id', c.client_id || '');
  setVal('tok-redirect-uri', c.redirect_uri || '');
  setVal('ref-token-url', c.token_url || '');
  setVal('ref-client-id', c.client_id || '');
  setVal('ui-userinfo-url', c.userinfo_url || '');
  setVal('intr-url', c.introspection_url || '');
  setVal('intr-client-id', c.client_id || '');
}

// ── Discovery ─────────────────────────────────────────────────────────────────

async function discoverAndUpdate() {
  const issuerURL = getVal('cfg-issuer-url');
  if (!issuerURL) {
    alert('Enter an Issuer URL first');
    return;
  }
  try {
    const res = await fetch('/api/discover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuer_url: issuerURL, update_config: true }),
    });
    const result = await res.json();
    if (result.error) {
      showStatus('config-status', 'Discovery error: ' + result.error, true);
      return;
    }
    // Reload config to get updated endpoints
    await loadConfig();
    showStatus('config-status', 'Discovered & updated ✓');
    setTimeout(() => showStatus('config-status', ''), 2000);
  } catch (e) {
    showStatus('config-status', 'Error: ' + e.message, true);
  }
}

async function runDiscovery(updateConfig) {
  const issuerURL = getVal('disc-issuer-url');
  if (!issuerURL) {
    alert('Enter an Issuer URL');
    return;
  }
  try {
    const res = await fetch('/api/discover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuer_url: issuerURL, update_config: updateConfig }),
    });
    const result = await res.json();
    if (updateConfig && !result.error) await loadConfig();
    renderResult('disc-result', result);
  } catch (e) {
    renderError('disc-result', e.message);
  }
}

// ── Authorize ─────────────────────────────────────────────────────────────────

async function generatePKCE() {
  const method = getVal('auth-pkce-method');
  try {
    const res = await fetch('/api/pkce/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method }),
    });
    const data = await res.json();
    state.pkce = { verifier: data.code_verifier, challenge: data.code_challenge, method };
    setVal('auth-code-verifier', data.code_verifier);
    setVal('auth-code-challenge', data.code_challenge);
    setVal('auth-code-challenge-method', data.code_challenge_method);
  } catch (e) {
    alert('Failed to generate PKCE: ' + e.message);
  }
}

async function buildAuthorizeURL() {
  const extraParams = parseJSON(getVal('auth-extra-params'), {});
  const scopes = getVal('auth-scopes').split(/\s+/).filter(Boolean);

  const body = {
    authorization_url: getVal('auth-url'),
    client_id: getVal('auth-client-id'),
    redirect_uri: getVal('auth-redirect-uri'),
    scopes,
    response_type: getVal('auth-response-type'),
    response_mode: getVal('auth-response-mode'),
    state: getVal('auth-state'),
    nonce: getVal('auth-nonce'),
    code_challenge: getVal('auth-code-challenge'),
    code_challenge_method: getVal('auth-code-challenge-method'),
    code_verifier: getVal('auth-code-verifier'),
    extra_params: extraParams,
  };

  try {
    const res = await fetch('/api/authorize-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();

    // Reflect auto-generated state/nonce back into the fields so the user
    // can see what was used and copy it if needed.
    if (data.state) setVal('auth-state', data.state);
    if (data.nonce) setVal('auth-nonce', data.nonce);

    const el = document.getElementById('auth-result');
    el.classList.remove('hidden');
    el.innerHTML = '';

    // URL display
    const urlDiv = document.createElement('div');
    urlDiv.className = 'url-display';
    urlDiv.innerHTML = `<span>${escHtml(data.url)}</span>
      <button class="copy-btn" onclick="copyText(${JSON.stringify(data.url)})">Copy</button>`;
    el.appendChild(urlDiv);

    // Params table
    const section = makeResultSection('Parameters');
    const table = document.createElement('table');
    table.className = 'params-table';
    table.innerHTML = '<tr><th>Parameter</th><th>Value</th></tr>';
    for (const [k, v] of Object.entries(data.params || {})) {
      const row = document.createElement('tr');
      row.innerHTML = `<td>${escHtml(k)}</td><td>${escHtml(Array.isArray(v) ? v.join(', ') : v)}</td>`;
      table.appendChild(row);
    }
    section.body.appendChild(table);
    el.appendChild(section.el);

    // Open button
    const openBtn = document.createElement('button');
    openBtn.className = 'btn-secondary';
    openBtn.textContent = 'Open in Browser →';
    openBtn.onclick = () => window.open(data.url, '_blank');
    el.appendChild(openBtn);
  } catch (e) {
    renderError('auth-result', e.message);
  }
}

// ── Token Exchange ────────────────────────────────────────────────────────────

function copyFromAuthorize() {
  if (state.pkce.verifier) {
    setVal('tok-code-verifier', state.pkce.verifier);
  } else {
    alert('No code verifier found. Generate PKCE in the Authorize tab first.');
  }
}

async function exchangeToken() {
  const extraParams = parseJSON(getVal('tok-extra-params'), {});
  const body = {
    token_url: getVal('tok-token-url'),
    client_id: getVal('tok-client-id'),
    client_secret: getVal('tok-client-secret'),
    code: getVal('tok-code'),
    redirect_uri: getVal('tok-redirect-uri'),
    code_verifier: getVal('tok-code-verifier'),
    extra_params: extraParams,
  };
  try {
    const res = await fetch('/api/token/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await res.json();
    renderResult('tok-result', result);
    storeTokensFromResult(result);
  } catch (e) {
    renderError('tok-result', e.message);
  }
}

// ── Refresh ───────────────────────────────────────────────────────────────────

async function doRefresh() {
  const extraParams = parseJSON(getVal('ref-extra-params'), {});
  const body = {
    token_url: getVal('ref-token-url'),
    client_id: getVal('ref-client-id'),
    client_secret: getVal('ref-client-secret'),
    refresh_token: getVal('ref-refresh-token'),
    extra_params: extraParams,
  };
  try {
    const res = await fetch('/api/token/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await res.json();
    renderResult('ref-result', result);
    storeTokensFromResult(result);
  } catch (e) {
    renderError('ref-result', e.message);
  }
}

// ── UserInfo ──────────────────────────────────────────────────────────────────

async function fetchUserInfo() {
  const body = {
    userinfo_url: getVal('ui-userinfo-url'),
    access_token: getVal('ui-access-token'),
  };
  try {
    const res = await fetch('/api/userinfo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await res.json();
    renderResult('ui-result', result);
  } catch (e) {
    renderError('ui-result', e.message);
  }
}

// ── Introspect ────────────────────────────────────────────────────────────────

async function doIntrospect() {
  const body = {
    introspection_url: getVal('intr-url'),
    client_id: getVal('intr-client-id'),
    client_secret: getVal('intr-client-secret'),
    token: getVal('intr-token'),
    token_type_hint: getVal('intr-hint'),
  };
  try {
    const res = await fetch('/api/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await res.json();
    renderResult('intr-result', result);
  } catch (e) {
    renderError('intr-result', e.message);
  }
}

// ── JWT Decode ────────────────────────────────────────────────────────────────

async function decodeJWT() {
  const token = getVal('jwt-token').trim();
  if (!token) {
    alert('Paste a JWT first');
    return;
  }
  try {
    const res = await fetch('/api/jwt/decode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    const data = await res.json();

    const el = document.getElementById('jwt-result');
    el.classList.remove('hidden');
    el.innerHTML = '';

    if (data.error) {
      renderError('jwt-result', data.error);
      return;
    }

    for (const part of ['header', 'payload']) {
      const section = makeResultSection(part.charAt(0).toUpperCase() + part.slice(1));
      const pre = document.createElement('pre');
      pre.innerHTML = syntaxHighlight(JSON.stringify(data[part], null, 2));
      section.body.appendChild(pre);

      // For payload, annotate timestamps
      if (part === 'payload' && data.payload) {
        const hints = buildTimestampHints(data.payload);
        if (hints.length) {
          const hintDiv = document.createElement('div');
          hintDiv.style.cssText = 'margin-top:0.5rem;font-size:0.8rem;color:var(--text-muted)';
          hintDiv.innerHTML = hints.map(h => `<div>${escHtml(h)}</div>`).join('');
          section.body.appendChild(hintDiv);
        }
      }

      el.appendChild(section.el);
    }

    if (data.signature) {
      const section = makeResultSection('Signature');
      const pre = document.createElement('pre');
      pre.textContent = data.signature;
      pre.style.wordBreak = 'break-all';
      section.body.appendChild(pre);
      el.appendChild(section.el);
    }
  } catch (e) {
    renderError('jwt-result', e.message);
  }
}

function buildTimestampHints(payload) {
  const hints = [];
  const tsFields = ['exp', 'iat', 'nbf', 'auth_time'];
  for (const field of tsFields) {
    if (payload[field]) {
      const d = new Date(payload[field] * 1000);
      const expired = field === 'exp' && d < new Date();
      hints.push(`${field}: ${d.toISOString()}${expired ? ' (EXPIRED)' : ''}`);
    }
  }
  return hints;
}

// ── Full Flow ─────────────────────────────────────────────────────────────────

function renderFlowPreview() {
  const c = state.config;
  const el = document.getElementById('flow-config-preview');
  el.innerHTML = '';

  const rows = [
    ['issuer_url', c.issuer_url],
    ['authorization_url', c.authorization_url],
    ['token_url', c.token_url],
    ['client_id', c.client_id],
    ['redirect_uri', c.redirect_uri],
    ['scopes', (c.scopes || []).join(' ')],
    ['pkce', c.pkce_enabled ? `enabled (${c.pkce_method})` : 'disabled'],
  ];

  for (const [key, val] of rows) {
    const row = document.createElement('div');
    row.className = 'cfg-row';
    const missing = !val;
    row.innerHTML = `<span class="cfg-key">${key}</span>
      <span class="cfg-val ${missing ? 'missing' : 'ok'}">${val || '⚠ not set'}</span>`;
    el.appendChild(row);
  }
}

function startFlow() {
  window.location.href = '/auth/start';
}

// ── History ───────────────────────────────────────────────────────────────────

async function loadHistory(highlightId) {
  try {
    const res = await fetch('/api/history');
    const entries = await res.json();
    renderHistory(entries, highlightId);
  } catch (_) {}
}

function renderHistory(entries, highlightId) {
  const el = document.getElementById('history-list');
  el.innerHTML = '';
  if (!entries || entries.length === 0) {
    el.innerHTML = '<p style="color:var(--text-muted);margin:0">No flows yet. Use Full Flow or Authorize → Open in Browser to start one.</p>';
    return;
  }
  for (const entry of entries) {
    renderHistoryEntry(el, entry, entry.id === highlightId);
  }
}

function renderHistoryEntry(container, entry, expanded) {
  const wrap = document.createElement('div');
  wrap.style.cssText = 'border:1px solid var(--border);border-radius:6px;margin-bottom:0.75rem;overflow:hidden';
  if (expanded) wrap.style.borderColor = 'var(--green)';

  const hasError = !!(entry.result && entry.result.error);
  const ts = new Date(entry.created_at).toLocaleString();
  const dot = hasError ? '🔴' : '🟢';

  const header = document.createElement('div');
  header.style.cssText = 'padding:0.6rem 1rem;cursor:pointer;display:flex;justify-content:space-between;align-items:center;background:var(--bg3);user-select:none';
  header.innerHTML = `<span>${dot} ${escHtml(ts)}</span><span style="color:var(--text-muted);font-size:0.8rem">${escHtml(entry.id)}</span>`;

  const body = document.createElement('div');
  body.style.cssText = 'padding:0.75rem 1rem 1rem';
  body.style.display = expanded ? '' : 'none';

  header.addEventListener('click', () => {
    body.style.display = body.style.display === 'none' ? '' : 'none';
  });

  if (entry.result) {
    buildHistoryBody(body, entry);
  }

  wrap.appendChild(header);
  wrap.appendChild(body);
  container.appendChild(wrap);

  if (expanded) wrap.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function buildHistoryBody(container, entry) {
  const result = entry.result;

  if (result.error) {
    const div = document.createElement('div');
    div.style.cssText = 'color:var(--red);background:rgba(248,81,73,0.1);border:1px solid var(--red);border-radius:6px;padding:0.75rem;margin-bottom:0.5rem;font-size:0.85rem';
    div.textContent = result.error;
    container.appendChild(div);
  }

  let parsed = null;
  if (result.response) {
    try { parsed = JSON.parse(result.response.body); } catch (_) {}
  }

  // Build inner tabs
  const innerTabs = [];

  if (result.response) {
    innerTabs.push({
      label: 'Token Response',
      build(el) {
        const status = result.response.status;
        const statusClass = status >= 500 ? 'status-5xx' : status >= 400 ? 'status-4xx' : 'status-2xx';
        const badge = document.createElement('span');
        badge.className = `status-badge ${statusClass}`;
        badge.textContent = status;
        badge.style.cssText = 'display:inline-block;margin-bottom:0.5rem';
        el.appendChild(badge);

        const pre = document.createElement('pre');
        let bodyStr = result.response.body;
        try { bodyStr = JSON.stringify(JSON.parse(bodyStr), null, 2); } catch (_) {}
        pre.innerHTML = syntaxHighlight(bodyStr);
        el.appendChild(pre);

        if (result.request) {
          const section = makeResultSection('Request');
          const reqPre = document.createElement('pre');
          reqPre.innerHTML = syntaxHighlight(JSON.stringify(result.request, null, 2));
          section.body.appendChild(reqPre);
          section.body.style.display = 'none';
          el.appendChild(section.el);
        }
      },
    });
  }

  if (parsed?.access_token) {
    innerTabs.push({
      label: 'Access Token',
      async build(el) { await renderJWTInline(el, parsed.access_token); },
    });
  }

  if (parsed?.id_token) {
    innerTabs.push({
      label: 'ID Token',
      async build(el) { await renderJWTInline(el, parsed.id_token); },
    });
  }

  if (entry.callback_params && Object.keys(entry.callback_params).length > 0) {
    innerTabs.push({
      label: 'Auth Response',
      build(el) {
        const table = document.createElement('table');
        table.className = 'params-table';
        table.innerHTML = '<tr><th>Parameter</th><th>Value</th></tr>';
        for (const [k, v] of Object.entries(entry.callback_params)) {
          const row = document.createElement('tr');
          row.innerHTML = `<td>${escHtml(k)}</td><td style="word-break:break-all">${escHtml(v)}</td>`;
          table.appendChild(row);
        }
        el.appendChild(table);
      },
    });
  }

  if (innerTabs.length > 0) {
    container.appendChild(makeInnerTabs(innerTabs));
  }

  // Action buttons
  if (parsed) {
    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:0.5rem';

    if (parsed.access_token) {
      addActionBtn(actions, 'UserInfo →', () => {
        setVal('ui-access-token', parsed.access_token);
        switchTab('userinfo');
      });
      addActionBtn(actions, 'Introspect →', () => {
        setVal('intr-token', parsed.access_token);
        switchTab('introspect');
      });
    }

    if (parsed.refresh_token) {
      const refreshBtn = document.createElement('button');
      refreshBtn.className = 'btn-secondary';
      refreshBtn.textContent = '↻ Refresh';
      let refreshContainer = null;
      refreshBtn.onclick = async () => {
        if (!refreshContainer) {
          refreshContainer = document.createElement('div');
          refreshContainer.style.cssText = 'width:100%;margin-top:0.75rem;border-top:1px solid var(--border);padding-top:0.75rem';
          actions.after(refreshContainer);
        } else {
          refreshContainer.innerHTML = '';
        }
        refreshBtn.disabled = true;
        refreshBtn.textContent = '↻ Refreshing…';
        await doInlineRefresh(refreshContainer, parsed.refresh_token);
        refreshBtn.disabled = false;
        refreshBtn.textContent = '↻ Refresh';
      };
      actions.appendChild(refreshBtn);
    }

    if (actions.children.length > 0) container.appendChild(actions);
  }
}

function makeInnerTabs(tabs) {
  const wrap = document.createElement('div');
  wrap.className = 'inner-tabs-wrap';

  const nav = document.createElement('div');
  nav.className = 'inner-tabs';

  const body = document.createElement('div');
  body.className = 'inner-tabs-body';

  const contentEls = [];
  const built = new Set();

  tabs.forEach((tab, i) => {
    const btn = document.createElement('button');
    btn.className = 'inner-tab-btn' + (i === 0 ? ' active' : '');
    btn.textContent = tab.label;
    nav.appendChild(btn);

    const content = document.createElement('div');
    content.className = 'inner-tab-content' + (i === 0 ? ' active' : '');
    contentEls.push(content);
    body.appendChild(content);

    function buildContent() {
      if (built.has(i)) return;
      built.add(i);
      const p = tab.build(content);
      if (p && p.then) {
        p.catch(e => {
          content.innerHTML += `<div style="color:var(--red);font-size:0.85rem">Error: ${escHtml(e.message)}</div>`;
        });
      }
    }

    if (i === 0) buildContent();

    btn.addEventListener('click', () => {
      nav.querySelectorAll('.inner-tab-btn').forEach(b => b.classList.remove('active'));
      contentEls.forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      content.classList.add('active');
      buildContent();
    });
  });

  wrap.appendChild(nav);
  wrap.appendChild(body);
  return wrap;
}

async function renderJWTInline(container, token) {
  try {
    const res = await fetch('/api/jwt/decode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    const data = await res.json();
    if (data.error) {
      container.innerHTML = `<div style="color:var(--red);font-size:0.85rem">${escHtml(data.error)}</div>`;
      return;
    }
    for (const part of ['header', 'payload']) {
      const section = makeResultSection(part.charAt(0).toUpperCase() + part.slice(1));
      const pre = document.createElement('pre');
      pre.innerHTML = syntaxHighlight(JSON.stringify(data[part], null, 2));
      section.body.appendChild(pre);
      if (part === 'payload' && data.payload) {
        const hints = buildTimestampHints(data.payload);
        if (hints.length) {
          const hintDiv = document.createElement('div');
          hintDiv.style.cssText = 'margin-top:0.5rem;font-size:0.8rem;color:var(--text-muted)';
          hintDiv.innerHTML = hints.map(h => `<div>${escHtml(h)}</div>`).join('');
          section.body.appendChild(hintDiv);
        }
      }
      container.appendChild(section.el);
    }
  } catch (e) {
    container.innerHTML = `<div style="color:var(--red);font-size:0.85rem">${escHtml(e.message)}</div>`;
  }
}

async function doInlineRefresh(container, refreshToken) {
  try {
    const res = await fetch('/api/token/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token_url: state.config.token_url,
        client_id: state.config.client_id,
        client_secret: state.config.client_secret,
        refresh_token: refreshToken,
        extra_params: state.config.extra_token_params || {},
      }),
    });
    const result = await res.json();

    if (result.error) {
      const errDiv = document.createElement('div');
      errDiv.style.cssText = 'color:var(--red);background:rgba(248,81,73,0.1);border:1px solid var(--red);border-radius:6px;padding:0.75rem;font-size:0.85rem';
      errDiv.textContent = result.error;
      container.appendChild(errDiv);
      return;
    }

    let parsed = null;
    if (result.response) {
      try { parsed = JSON.parse(result.response.body); } catch (_) {}
    }

    const innerTabs = [];

    if (result.response) {
      innerTabs.push({
        label: 'Token Response',
        build(el) {
          const status = result.response.status;
          const statusClass = status >= 500 ? 'status-5xx' : status >= 400 ? 'status-4xx' : 'status-2xx';
          const badge = document.createElement('span');
          badge.className = `status-badge ${statusClass}`;
          badge.textContent = status;
          badge.style.cssText = 'display:inline-block;margin-bottom:0.5rem';
          el.appendChild(badge);
          const pre = document.createElement('pre');
          let bodyStr = result.response.body;
          try { bodyStr = JSON.stringify(JSON.parse(bodyStr), null, 2); } catch (_) {}
          pre.innerHTML = syntaxHighlight(bodyStr);
          el.appendChild(pre);
        },
      });
    }

    if (parsed?.access_token) {
      innerTabs.push({
        label: 'Access Token',
        async build(el) { await renderJWTInline(el, parsed.access_token); },
      });
    }
    if (parsed?.id_token) {
      innerTabs.push({
        label: 'ID Token',
        async build(el) { await renderJWTInline(el, parsed.id_token); },
      });
    }

    if (innerTabs.length > 0) container.appendChild(makeInnerTabs(innerTabs));
  } catch (e) {
    container.innerHTML = `<div style="color:var(--red);font-size:0.85rem">${escHtml(e.message)}</div>`;
  }
}

function addActionBtn(container, label, onclick) {
  const btn = document.createElement('button');
  btn.className = 'btn-secondary';
  btn.textContent = label;
  btn.onclick = onclick;
  container.appendChild(btn);
}

// ── Rendering ─────────────────────────────────────────────────────────────────

function renderResult(elId, result) {
  const el = document.getElementById(elId);
  el.classList.remove('hidden');
  el.innerHTML = '';

  if (result.error) {
    const errDiv = document.createElement('div');
    errDiv.style.cssText = 'color:var(--red);background:rgba(248,81,73,0.1);border:1px solid var(--red);border-radius:6px;padding:0.75rem 1rem;font-family:var(--font-mono);font-size:0.85rem';
    errDiv.textContent = 'Error: ' + result.error;
    el.appendChild(errDiv);
  }

  if (result.request) {
    const section = makeResultSection('Request');
    section.el.style.marginBottom = '0.5rem';
    const pre = document.createElement('pre');
    pre.innerHTML = syntaxHighlight(JSON.stringify(result.request, null, 2));
    section.body.appendChild(pre);
    el.appendChild(section.el);
  }

  if (result.response) {
    const status = result.response.status;
    const statusClass = status >= 500 ? 'status-5xx' : status >= 400 ? 'status-4xx' : 'status-2xx';
    const section = makeResultSection('Response',
      `<span class="status-badge ${statusClass}">${status}</span>`);
    const pre = document.createElement('pre');

    let bodyStr = result.response.body;
    try {
      bodyStr = JSON.stringify(JSON.parse(bodyStr), null, 2);
    } catch (_) {}
    pre.innerHTML = syntaxHighlight(bodyStr);
    section.body.appendChild(pre);
    el.appendChild(section.el);

    // Extract and offer JWT decode for tokens
    try {
      const parsed = JSON.parse(result.response.body);
      addJWTButtons(el, parsed);
    } catch (_) {}
  }
}

function addJWTButtons(container, tokenResponse) {
  const jwtFields = ['access_token', 'id_token', 'refresh_token'];
  const found = jwtFields.filter(f => tokenResponse[f] && tokenResponse[f].includes('.'));
  if (!found.length) return;

  const div = document.createElement('div');
  div.style.cssText = 'display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:0.5rem';
  for (const field of found) {
    const btn = document.createElement('button');
    btn.className = 'btn-secondary';
    btn.textContent = `Decode ${field}`;
    btn.onclick = () => {
      setVal('jwt-token', tokenResponse[field]);
      switchTab('jwt');
      decodeJWT();
    };
    div.appendChild(btn);

    // Pre-fill access token for userinfo
    if (field === 'access_token') {
      const uiBtn = document.createElement('button');
      uiBtn.className = 'btn-secondary';
      uiBtn.textContent = 'Use as access_token';
      uiBtn.onclick = () => {
        setVal('ui-access-token', tokenResponse[field]);
        setVal('intr-token', tokenResponse[field]);
        switchTab('userinfo');
      };
      div.appendChild(uiBtn);
    }

    if (field === 'refresh_token') {
      const refBtn = document.createElement('button');
      refBtn.className = 'btn-secondary';
      refBtn.textContent = 'Use for refresh';
      refBtn.onclick = () => {
        setVal('ref-refresh-token', tokenResponse[field]);
        switchTab('refresh');
      };
      div.appendChild(refBtn);
    }
  }
  container.appendChild(div);
}

function storeTokensFromResult(result) {
  if (!result.response) return;
  try {
    const parsed = JSON.parse(result.response.body);
    if (parsed.access_token) setVal('ui-access-token', parsed.access_token);
    if (parsed.access_token) setVal('intr-token', parsed.access_token);
    if (parsed.refresh_token) setVal('ref-refresh-token', parsed.refresh_token);
  } catch (_) {}
}

function renderError(elId, msg) {
  const el = document.getElementById(elId);
  el.classList.remove('hidden');
  el.innerHTML = `<div style="color:var(--red);font-family:var(--font-mono);padding:0.75rem">${escHtml(msg)}</div>`;
}

function makeResultSection(title, badgeHtml = '') {
  const el = document.createElement('div');
  el.className = 'result-section';
  const header = document.createElement('div');
  header.className = 'result-section-header';
  header.innerHTML = `<span>${title}</span>${badgeHtml}`;
  const body = document.createElement('div');
  body.className = 'result-section-body';
  el.appendChild(header);
  el.appendChild(body);
  header.addEventListener('click', () => {
    body.style.display = body.style.display === 'none' ? '' : 'none';
  });
  return { el, body };
}

// ── Syntax Highlighting ───────────────────────────────────────────────────────

function syntaxHighlight(str) {
  if (typeof str !== 'string') str = JSON.stringify(str, null, 2);
  return str.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, match => {
    let cls = 'json-num';
    if (/^"/.test(match)) {
      cls = /:$/.test(match) ? 'json-key' : 'json-str';
    } else if (/true|false/.test(match)) {
      cls = 'json-bool';
    } else if (/null/.test(match)) {
      cls = 'json-null';
    }
    return `<span class="${cls}">${escHtml(match)}</span>`;
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getVal(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : '';
}

function setVal(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val || '';
}

function setSelectVal(id, val) {
  const el = document.getElementById(id);
  if (!el) return;
  for (const opt of el.options) {
    if (opt.value === val) { opt.selected = true; return; }
  }
}

function parseJSON(str, fallback) {
  if (!str || !str.trim()) return fallback;
  try { return JSON.parse(str); }
  catch (_) { return fallback; }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showStatus(id, msg, isError = false) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className = 'status-msg' + (isError ? ' error' : '');
}

function toggleSecret(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.type = el.type === 'password' ? 'text' : 'password';
}

function copyField(id) {
  const val = document.getElementById(id)?.value;
  if (val) copyText(val);
}

function copyText(text) {
  navigator.clipboard.writeText(text).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

async function genRandom(id, bytes) {
  try {
    const res = await fetch('/api/pkce/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'plain' }),
    });
    const data = await res.json();
    // code_verifier is a good random string (32 bytes base64url)
    setVal(id, data.code_verifier.slice(0, bytes * 2));
  } catch (_) {
    // Fallback: browser crypto
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    const b64 = btoa(String.fromCharCode(...arr))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    setVal(id, b64);
  }
}

function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => {
    if (b.dataset.tab === name) b.click();
  });
}
