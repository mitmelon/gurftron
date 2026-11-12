'use strict';

const path = require('node:path');
const { Readable } = require('node:stream');
const Fastify = require('fastify');
const fastifyStatic = require('@fastify/static');

const { createClient, LoaderError } = require('./loader-client');
const { runPipeline } = require('./pipeline');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '127.0.0.1';
const LOADER_URL = process.env.LOADER_URL || 'http://127.0.0.1:3000';

function buildApp({ loader = createClient({ baseUrl: LOADER_URL }), logger = true } = {}) {
  const app = Fastify({ logger, bodyLimit: 1024 * 1024 });

  app.register(fastifyStatic, { root: path.join(__dirname, 'public'), prefix: '/' });

  // One error shape, the same one the loader uses.
  app.setErrorHandler((err, req, reply) => {
    if (err instanceof LoaderError) {
      return reply.code(err.status || 500).send({
        error: { code: err.code, message: err.message, model: err.model },
      });
    }
    if (err.validation) {
      return reply.code(400).send({
        error: { code: 'INVALID_REQUEST', message: err.message, model: null },
      });
    }
    req.log.error(err);
    return reply.code(err.statusCode || 500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Unexpected server error', model: null },
    });
  });

  const text = { type: 'string', minLength: 1, maxLength: 20000 };
  const model = { type: 'string', minLength: 1, maxLength: 64, pattern: '^[a-z0-9-]+$' };

  // Loader status + model list in one call. Never throws: "offline" is a normal state.
  app.get('/api/status', async () => {
    try {
      const [health, models] = await Promise.all([loader.health(), loader.models()]);
      return { loader: { online: true, url: loader.baseUrl }, health, models: models.models };
    } catch (err) {
      if (err instanceof LoaderError && err.code === 'LOADER_OFFLINE') {
        return { loader: { online: false, url: loader.baseUrl }, health: null, models: [] };
      }
      throw err;
    }
  });

  app.post(
    '/api/guard',
    { schema: { body: { type: 'object', required: ['model', 'input'], properties: { model, input: text } } } },
    async (req) => loader.guard(req.body.model, req.body.input),
  );

  app.post(
    '/api/classify',
    { schema: { body: { type: 'object', required: ['model', 'input'], properties: { model, input: text } } } },
    async (req) => loader.classify(req.body.model, req.body.input),
  );

  app.post(
    '/api/embed',
    {
      schema: {
        body: {
          type: 'object',
          required: ['model', 'input'],
          properties: { model, input: { anyOf: [text, { type: 'array', minItems: 1, maxItems: 64, items: text }] } },
        },
      },
    },
    async (req) => loader.embed(req.body.model, req.body.input),
  );

  const chatBody = {
    type: 'object',
    required: ['model', 'messages'],
    properties: {
      model,
      messages: {
        type: 'array',
        minItems: 1,
        maxItems: 64,
        items: {
          type: 'object',
          required: ['role', 'content'],
          properties: { role: { enum: ['system', 'user', 'assistant'] }, content: { type: 'string', maxLength: 20000 } },
        },
      },
      temperature: { type: 'number', minimum: 0, maximum: 2 },
      top_p: { type: 'number', minimum: 0, maximum: 1 },
      max_tokens: { type: 'integer', minimum: 1, maximum: 8192 },
      stop: { anyOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' }, maxItems: 8 }] },
      stream: { type: 'boolean' },
      format: { enum: ['json', 'text'] },
      guard: model,
    },
  };

  app.post('/api/chat', { schema: { body: chatBody } }, async (req, reply) => {
    const { model: name, messages, stream, ...opts } = req.body;
    if (!stream) return loader.chat(name, messages, opts);

    // Pass tokens through as server-sent events. Cancel the loader if the browser leaves.
    const abort = new AbortController();
    reply.raw.on('close', () => abort.abort());
    const tokens = loader.chatStream(name, messages, opts, abort.signal);

    // Pull the first token before sending headers, so load errors still come back as normal JSON errors.
    const iterator = tokens[Symbol.asyncIterator]();
    const first = await iterator.next();

    async function* events() {
      try {
        if (!first.done) yield `data: ${JSON.stringify({ token: first.value })}\n\n`;
        let step = first.done ? first : await iterator.next();
        while (!step.done) {
          yield `data: ${JSON.stringify({ token: step.value })}\n\n`;
          step = await iterator.next();
        }
      } catch (err) {
        if (!abort.signal.aborted) {
          const e = { code: err.code || 'INTERNAL_ERROR', message: err.message, model: err.model || null };
          yield `data: ${JSON.stringify({ error: e })}\n\n`;
        }
      }
      yield 'data: [DONE]\n\n';
    }

    return reply
      .header('Content-Type', 'text/event-stream; charset=utf-8')
      .header('Cache-Control', 'no-cache, no-transform')
      .header('X-Accel-Buffering', 'no')
      .send(Readable.from(events()));
  });

  app.post(
    '/api/pipeline',
    {
      schema: {
        body: {
          type: 'object',
          required: ['text'],
          properties: { text, guard: model, writer: model, classifier: model, embedder: model, system: { type: 'string', maxLength: 4000 } },
        },
      },
    },
    async (req) => runPipeline(loader, req.body),
  );

  return app;
}

async function main() {
  const app = buildApp();
  try {
    await app.listen({ port: PORT, host: HOST });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

if (require.main === module) main();

module.exports = { buildApp };
