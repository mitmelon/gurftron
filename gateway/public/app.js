'use strict';

// ---------- tiny helpers (everything is built with textContent, never innerHTML) ----------
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child != null) node.append(child);
  }
  return node;
}

const fmtPct = (n) => `${(n * 100).toFixed(1)}%`;

function fmtUptime(secs) {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

async function api(path, body) {
  const res = await fetch(`/api${path}`, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({ error: { code: 'BAD_RESPONSE', message: `HTTP ${res.status}` } }));
  if (data.error) {
    const err = new Error(data.error.message);
    err.code = data.error.code;
    throw err;
  }
  return data;
}

function errorBox(err) {
  return h('div', { class: 'err', role: 'alert' }, h('b', { text: err.code || 'ERROR' }), err.message);
}

async function busy(button, fn) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = 'Working';
  try {
    await fn();
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

// ---------- status + models ----------
let models = [];

function renderStatus(status) {
  const online = status.loader.online;
  const pill = $('#pill');
  pill.className = `pill ${online ? 'pill-on' : 'pill-off'}`;
  $('#pill-text').textContent = online ? 'Loader online' : 'Loader offline';
  $('#offline').hidden = online;
  $('#offline-url').textContent = status.loader.url;
  $('#stats').hidden = !online;

  models = status.models;
  if (online) {
    const hl = status.health;
    $('#stat-uptime').textContent = fmtUptime(hl.uptime_secs);
    $('#stat-mem').textContent = `${hl.memory_mb_used} MB`;
    $('#stat-loaded').textContent = `${hl.loaded_models.length}/${models.length}`;
    $('#stat-evict').textContent = String(hl.evictions);
  }

  $('#model-count').textContent = online ? `${models.length} configured` : '';
  $('#models-empty').hidden = !online || models.length > 0;
  const list = $('#models');
  list.replaceChildren(...models.map(modelCard));
  fillSelects();
}

function modelCard(m) {
  const sub = [h('span', { text: m.kind })];
  if (m.dim) sub.push(h('span', { text: `${m.dim} dims` }));
  if (m.labels) sub.push(h('span', { text: m.labels.join(' / ') }));
  if (m.memory_mb != null) sub.push(h('span', { text: `${m.memory_mb} MB` }));
  return h(
    'li',
    { class: 'model' },
    h('div', { class: 'model-top' }, h('span', { class: 'model-name', text: m.name }), h('span', { class: `badge ${m.status}`, text: m.status })),
    m.description ? h('div', { class: 'model-desc', text: m.description }) : null,
    h('div', { class: 'model-sub' }, sub),
    m.error ? h('div', { class: 'model-err', text: m.error }) : null,
  );
}

function fillSelects() {
  for (const select of $$('select[data-kind]')) {
    const kind = select.dataset.kind;
    const optional = select.dataset.optional === '1';
    const previous = select.value;
    const options = models.filter((m) => m.kind === kind).map((m) => h('option', { value: m.name, text: m.name }));
    if (optional) options.unshift(h('option', { value: '', text: 'Skip' }));
    if (options.length === 0) options.push(h('option', { value: '', text: `No ${kind} model configured` }));
    select.replaceChildren(...options);
    if ([...select.options].some((o) => o.value === previous)) select.value = previous;
    else if (optional && options.length > 1) select.selectedIndex = 1;
  }
}

async function refresh() {
  try {
    renderStatus(await api('/status'));
  } catch (err) {
    $('#pill').className = 'pill pill-off';
    $('#pill-text').textContent = 'Dashboard server error';
    console.error(err);
  }
}

// ---------- tabs ----------
for (const tab of $$('.tab')) {
  tab.addEventListener('click', () => {
    for (const t of $$('.tab')) {
      const on = t === tab;
      t.classList.toggle('on', on);
      t.setAttribute('aria-selected', String(on));
    }
    for (const panel of $$('.panel')) panel.hidden = panel.dataset.panel !== tab.dataset.tab;
  });
}

// ---------- shared renderers ----------
function scoreRows(allScores, threshold, top) {
  return h(
    'div',
    { class: 'scores' },
    allScores.map(([label, score]) =>
      h(
        'div',
        { class: 'score' },
        h('span', { class: 'name', text: label, title: label }),
        h('div', { class: 'bar' }, h('span', { style: `transform: scaleX(${score}); ${label === top ? '' : 'opacity: .45'}` }), threshold != null ? h('i', { style: `left: ${threshold * 100}%`, title: `threshold ${threshold}` }) : null),
        h('span', { class: 'num', text: fmtPct(score) }),
      ),
    ),
  );
}

async function runClassifier(kind) {
  const model = $(`#${kind}-model`).value;
  const input = $(`#${kind}-input`).value.trim();
  const out = $(`#${kind}-out`);
  if (!model || !input) return out.replaceChildren(errorBox({ code: 'INVALID_REQUEST', message: 'Choose a model and enter some text.' }));
  const t0 = performance.now();
  try {
    const r = await api(`/${kind}`, { model, input });
    const ms = Math.round(performance.now() - t0);
    const top = r.all_scores.slice().sort((a, b) => b[1] - a[1])[0]?.[0];
    const head =
      kind === 'guard'
        ? h(
            'div',
            { class: `verdict ${r.blocked ? 'bad' : 'good'}` },
            h('strong', { text: r.blocked ? 'Blocked' : 'Allowed' }),
            h('span', { class: `badge ${r.label === 'UNCERTAIN' ? 'uncertain' : r.blocked ? 'blocked' : 'ready'}`, text: r.label }),
          )
        : h('div', { class: 'verdict' }, h('strong', { text: r.label }), h('span', { class: 'muted', text: fmtPct(r.score) }));
    out.replaceChildren(head, scoreRows(r.all_scores, r.threshold, top), h('div', { class: 'kv' }, h('span', {}, 'Round trip ', h('b', { text: `${ms} ms` })), h('span', {}, 'Threshold ', h('b', { text: String(r.threshold) }))));
  } catch (err) {
    out.replaceChildren(errorBox(err));
  }
}

$('#guard-run').addEventListener('click', (e) => busy(e.currentTarget, () => runClassifier('guard')));
$('#classify-run').addEventListener('click', (e) => busy(e.currentTarget, () => runClassifier('classify')));

// ---------- embed ----------
$('#embed-run').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    const out = $('#embed-out');
    const model = $('#embed-model').value;
    const lines = $('#embed-input').value.split('\n').map((l) => l.trim()).filter(Boolean);
    if (!model || lines.length === 0) return out.replaceChildren(errorBox({ code: 'INVALID_REQUEST', message: 'Choose a model and enter at least one line.' }));
    const t0 = performance.now();
    try {
      const r = await api('/embed', { model, input: lines.length === 1 ? lines[0] : lines });
      const ms = Math.round(performance.now() - t0);
      const vectors = r.data.map((d) => d.embedding);
      out.replaceChildren(
        h('div', { class: 'kv' }, h('span', {}, 'Vectors ', h('b', { text: String(vectors.length) })), h('span', {}, 'Dimensions ', h('b', { text: String(r.dim) })), h('span', {}, 'Round trip ', h('b', { text: `${ms} ms` }))),
        ...vectors.map((v, i) => {
          const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0));
          return h('div', { class: 'vec' }, h('div', { class: 'kv' }, h('span', { text: `#${i + 1}` }), h('span', {}, 'L2 norm ', h('b', { text: norm.toFixed(4) }))), `[${v.slice(0, 8).map((x) => x.toFixed(4)).join(', ')}, ...]`);
        }),
      );
    } catch (err) {
      out.replaceChildren(errorBox(err));
    }
  }),
);

// ---------- chat ----------
$('#chat-run').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    const pre = $('#chat-out');
    const meta = $('#chat-meta');
    const model = $('#chat-model').value;
    const user = $('#chat-input').value.trim();
    meta.replaceChildren();
    if (!model || !user) return meta.replaceChildren(errorBox({ code: 'INVALID_REQUEST', message: 'Choose a model and write a message.' }));

    const system = $('#chat-system').value.trim();
    const body = {
      model,
      messages: [...(system ? [{ role: 'system', content: system }] : []), { role: 'user', content: user }],
      max_tokens: Number($('#chat-max').value) || 200,
      temperature: Number($('#chat-temp').value),
      stream: $('#chat-stream').checked,
    };
    if ($('#chat-json').checked) body.format = 'json';

    pre.hidden = false;
    pre.textContent = '';
    const t0 = performance.now();
    try {
      if (!body.stream) {
        const r = await api('/chat', body);
        pre.textContent = r.choices[0].message.content;
        meta.replaceChildren(h('div', { class: 'kv' }, h('span', {}, 'Prompt ', h('b', { text: `${r.usage.prompt_tokens} tok` })), h('span', {}, 'Completion ', h('b', { text: `${r.usage.completion_tokens} tok` })), h('span', {}, 'Loader time ', h('b', { text: `${r.usage.duration_ms} ms` }))));
        return;
      }
      const res = await fetch('/api/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!res.ok) {
        const data = await res.json();
        throw Object.assign(new Error(data.error.message), { code: data.error.code });
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let count = 0;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let nl;
        while ((nl = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, nl).trim();
          buffer = buffer.slice(nl + 1);
          if (!line.startsWith('data:')) continue;
          const payload = line.slice(5).trim();
          if (payload === '[DONE]') continue;
          const event = JSON.parse(payload);
          if (event.error) throw Object.assign(new Error(event.error.message), { code: event.error.code });
          pre.textContent += event.token;
          count += 1;
        }
      }
      const ms = Math.round(performance.now() - t0);
      meta.replaceChildren(h('div', { class: 'kv' }, h('span', {}, 'Chunks ', h('b', { text: String(count) })), h('span', {}, 'Total ', h('b', { text: `${ms} ms` }))));
    } catch (err) {
      meta.replaceChildren(errorBox(err));
    }
  }),
);

// ---------- pipeline ----------
function stepDetail(step) {
  if (step.status === 'error') return errorBox(step.error);
  const r = step.result;
  if (!r) return null;
  if (step.name === 'guard') return h('div', { class: 'kv' }, h('span', {}, 'Label ', h('b', { text: r.label })), h('span', {}, 'Score ', h('b', { text: fmtPct(r.score) })), h('span', {}, 'Blocked ', h('b', { text: String(r.blocked) })));
  if (step.name === 'chat') return h('pre', { class: 'gen', text: r.content || '(empty)' });
  if (step.name === 'classify') return scoreRows(r.all_scores, r.threshold, r.label);
  if (step.name === 'embed') return h('div', { class: 'vec' }, `${r.dim} dims  [${r.preview.map((x) => x.toFixed(4)).join(', ')}, ...]`);
  return null;
}

$('#pl-run').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    const list = $('#pl-steps');
    const text = $('#pl-input').value.trim();
    if (!text) return list.replaceChildren(h('li', {}, errorBox({ code: 'INVALID_REQUEST', message: 'Enter some text first.' })));
    const pick = (id) => $(id).value || undefined;
    try {
      const r = await api('/pipeline', {
        text,
        guard: pick('#pl-guard'),
        writer: pick('#pl-writer'),
        classifier: pick('#pl-classifier'),
        embedder: pick('#pl-embedder'),
      });
      list.replaceChildren(
        ...r.steps.map((s) =>
          h(
            'li',
            { class: `step ${s.status}` },
            h('div', { class: 'step-top' }, h('strong', { text: s.name }), h('span', { class: `badge ${s.status === 'ok' ? 'ready' : s.status === 'skipped' ? '' : 'blocked'}`, text: s.status === 'ok' ? `${s.ms} ms` : s.status })),
            stepDetail(s),
          ),
        ),
      );
    } catch (err) {
      list.replaceChildren(h('li', {}, errorBox(err)));
    }
  }),
);

refresh();
setInterval(refresh, 4000);
