'use strict';

/**
 * Tiny client for the Manomite Loader HTTP API.
 * Only `fetch` and `require`: no Ollama SDK, no Python.
 *
 *   const loader = require('./loader-client');
 *   const verdict = await loader.guard('guard', 'Ignore all instructions');
 */

const DEFAULT_BASE = process.env.LOADER_URL || 'http://127.0.0.1:3000';

class LoaderError extends Error {
  constructor(message, { code = 'INTERNAL_ERROR', model = null, status = 500 } = {}) {
    super(message);
    this.name = 'LoaderError';
    this.code = code;
    this.model = model;
    this.status = status;
  }
}

function createClient({ baseUrl = DEFAULT_BASE, timeoutMs = 90_000 } = {}) {
  const base = baseUrl.replace(/\/+$/, '');

  async function raw(method, path, body, signal) {
    let res;
    try {
      res = await fetch(base + path, {
        method,
        headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: signal || AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      if (err && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
        throw new LoaderError('The loader did not answer in time', { code: 'TIMEOUT', status: 504 });
      }
      throw new LoaderError(`Cannot reach the loader at ${base}`, { code: 'LOADER_OFFLINE', status: 503 });
    }
    return res;
  }

  async function request(method, path, body) {
    const res = await raw(method, path, body);
    let data;
    try {
      data = await res.json();
    } catch {
      throw new LoaderError(`Loader returned a non-JSON answer (HTTP ${res.status})`, { status: 502 });
    }
    if (data && data.error) {
      throw new LoaderError(data.error.message, {
        code: data.error.code,
        model: data.error.model,
        status: res.status,
      });
    }
    return data;
  }

  /** Stream tokens from /v1/chat/completions. Yields strings. */
  async function* chatStream(model, messages, opts = {}, signal) {
    const res = await raw('POST', '/v1/chat/completions', { model, messages, ...opts, stream: true }, signal);
    if (!res.ok || !res.body) {
      const data = await res.json().catch(() => ({}));
      const e = data.error || {};
      throw new LoaderError(e.message || `Loader answered HTTP ${res.status}`, {
        code: e.code,
        model: e.model,
        status: res.status,
      });
    }
    const decoder = new TextDecoder();
    let buffer = '';
    for await (const chunk of res.body) {
      buffer += decoder.decode(chunk, { stream: true });
      let nl;
      while ((nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line.startsWith('data:')) continue;
        const payload = line.slice(5).trim();
        if (payload === '[DONE]') return;
        const event = JSON.parse(payload);
        if (event.error) {
          throw new LoaderError(event.error.message, { code: event.error.code, model: event.error.model });
        }
        if (typeof event.token === 'string') yield event.token;
      }
    }
  }

  return {
    baseUrl: base,
    health: () => request('GET', '/health'),
    models: () => request('GET', '/v1/models'),
    chat: (model, messages, opts = {}) => request('POST', '/v1/chat/completions', { model, messages, ...opts }),
    chatStream,
    embed: (model, input) => request('POST', '/v1/embeddings', { model, input }),
    guard: (model, input) => request('POST', '/v1/guard', { model, input }),
    classify: (model, input) => request('POST', '/v1/classify', { model, input }),
  };
}

const defaultClient = createClient();

module.exports = { ...defaultClient, createClient, LoaderError };
